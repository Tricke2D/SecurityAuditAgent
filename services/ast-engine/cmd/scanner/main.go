package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"security-audit-agent/ast-engine/internal/callgraph"
	"security-audit-agent/ast-engine/internal/parser"
	"security-audit-agent/ast-engine/internal/patterns"
	"security-audit-agent/ast-engine/internal/scanner"
	"security-audit-agent/ast-engine/internal/storage"
	"security-audit-agent/ast-engine/internal/taint"
)

func main() {
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	scanPath := scanCmd.String("path", "", "path folder codebase yang akan di-scan")

	reportCmd := flag.NewFlagSet("report", flag.ExitOnError)

	taintCmd := flag.NewFlagSet("taint", flag.ExitOnError)
	taintPath := taintCmd.String("path", "", "path folder codebase untuk taint analysis")

	if len(os.Args) < 2 {
		fmt.Println("usage: scanner [scan|report|taint] [flags]")
		os.Exit(1)
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/security_audit?sslmode=disable"
	}

	store, err := storage.NewStore(dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		scanCmd.Parse(os.Args[2:])
		if *scanPath == "" {
			fmt.Println("error: --path wajib diisi")
			os.Exit(1)
		}
		runScan(store, *scanPath)

	case "report":
		reportCmd.Parse(os.Args[2:])
		runReport(store)

	case "taint":
		taintCmd.Parse(os.Args[2:])
		if *taintPath == "" {
			fmt.Println("error: --path wajib diisi")
			os.Exit(1)
		}
		runTaintAnalysis(store, *taintPath)

	default:
		fmt.Printf("unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func runScan(store *storage.Store, path string) {
	matchers := []patterns.PatternMatcher{
		patterns.NewSQLInjectionMatcher(),
		patterns.NewHardcodedSecretMatcher(),
		patterns.NewDangerousEvalMatcher(),
		patterns.NewInsecureDeserializeMatcher(),
	}

	s := scanner.NewScanner(matchers)
	results, err := s.ScanDirectory(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	totalFindings := 0
	for _, result := range results {
		if err := store.SaveScanResult(ctx, result); err != nil {
			fmt.Fprintf(os.Stderr, "failed to save result for %s: %v\n", result.FilePath, err)
			continue
		}
		totalFindings += len(result.Findings)
	}

	fmt.Printf("Scan selesai: %d file diproses, %d finding ditemukan (raw, belum difilter).\n",
		len(results), totalFindings)
}

func runReport(store *storage.Store) {
	ctx := context.Background()
	findings, err := store.GetAllFindings(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "report error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== Static Analysis Report (RAW — %d findings) ===\n\n", len(findings))
	for _, f := range findings {
		fmt.Printf("[%s] %s:%d — %s\n    %s\n\n",
			f.RawSeverity, f.FilePath, f.LineNumber, f.PatternType, f.MatchedSnippet)
	}
}

func runTaintAnalysis(store *storage.Store, path string) {
	fmt.Println("=== FASE 2: Call Graph & Taint Analysis ===")
	fmt.Printf("Analyzing: %s\n\n", path)

	files, err := parser.ParseDirectory(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Parsed %d files\n", len(files))

	if len(files) == 0 {
		fmt.Println("No files to analyze")
		return
	}

	// Build call graph
	builder := callgraph.NewBuilder()
	graph := builder.BuildFromFiles(files)

	fmt.Printf("Call graph: %d functions, %d calls\n", graph.NodeCount(), graph.EdgeCount())

	// Taint Analysis
	fmt.Println("\n=== Taint Analysis ===")
	propagator := taint.NewPropagator(graph, files)

	ctx := context.Background()
	totalFlows := 0

	for _, file := range files {
		lines := file.GetLines()
		for i, line := range lines {
			if strings.Contains(line, "request.GET") ||
				strings.Contains(line, "request.POST") ||
				strings.Contains(line, "request.args") ||
				strings.Contains(line, "request.form") ||
				strings.Contains(line, "input(") {

				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					varName := strings.TrimSpace(parts[0])
					varName = strings.Split(varName, ":")[0]
					varName = strings.TrimSpace(varName)

					if varName != "" {
						initial := taint.TaintedVariable{
							VariableName:  varName,
							FilePath:      file.FilePath,
							Line:          i + 1,
							QualifiedFunc: "unknown",
						}

						result := propagator.TracePropagation(initial)
						if result.ReachedSink {
							totalFlows++
							fmt.Printf("✅ Found taint flow!\n")
							fmt.Printf("  Source: %s:%d (%s)\n", file.FilePath, i+1, varName)
							fmt.Printf("  Sink: %s:%d\n", result.SinkFile, result.SinkLine)
							fmt.Printf("  Path length: %d steps\n", len(result.FlowPath))
							for _, step := range result.FlowPath {
								fmt.Printf("    → %s:%d [%s]\n", step.FilePath, step.Line, step.Kind)
							}
							fmt.Println()

							// SAVE TO DATABASE
							saveTaintFlow(ctx, store, file.FilePath, result)
						}
					}
				}
			}
		}
	}

	fmt.Printf("\n✅ Taint analysis completed! Found %d flows\n", totalFlows)
}

// saveTaintFlow menyimpan taint flow ke database
// Mencari source_finding_id dan sink_finding_id berdasarkan file path
// dan pattern_type = 'sql_injection'
func saveTaintFlow(ctx context.Context, store *storage.Store, sourceFile string, result taint.TaintResult) {
	db := store.GetDB()

	// Cari source_finding_id berdasarkan file dan pattern_type = sql_injection
	var sourceFindingID int64
	query := `SELECT sf.id FROM static_findings sf
	          JOIN codebase_files cf ON cf.id = sf.file_id
	          WHERE cf.file_path = $1 AND sf.pattern_type = 'sql_injection'
	          ORDER BY sf.line_number ASC LIMIT 1`

	err := db.QueryRowContext(ctx, query, sourceFile).Scan(&sourceFindingID)
	if err != nil {
		fmt.Printf("  ⚠️ Error finding source finding for %s: %v\n", sourceFile, err)
		return
	}

	// Cari sink_finding_id berdasarkan sink file dan pattern_type = sql_injection
	var sinkFindingID int64
	err = db.QueryRowContext(ctx, query, result.SinkFile).Scan(&sinkFindingID)
	if err != nil {
		fmt.Printf("  ⚠️ Error finding sink finding for %s: %v\n", result.SinkFile, err)
		return
	}

	if sourceFindingID == 0 || sinkFindingID == 0 {
		fmt.Printf("  ⚠️ Warning: Cannot find finding IDs for source or sink\n")
		return
	}

	// Insert taint flow
	insertQuery := `INSERT INTO taint_flows 
	                (source_finding_id, sink_finding_id, flow_path, is_sanitized, sanitization_detail)
	                VALUES ($1, $2, $3, $4, $5)`

	flowPathJSON, _ := json.Marshal(result.FlowPath)
	_, err = db.ExecContext(ctx, insertQuery,
		sourceFindingID, sinkFindingID, flowPathJSON, false, nil)

	if err != nil {
		fmt.Printf("  ⚠️ Error saving taint flow: %v\n", err)
	} else {
		fmt.Printf("  💾 Taint flow saved to database (source_finding_id=%d, sink_finding_id=%d)\n", sourceFindingID, sinkFindingID)
	}
}