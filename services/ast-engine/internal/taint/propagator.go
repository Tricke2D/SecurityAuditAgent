package taint

import (
	"regexp"
	"strings"

	"security-audit-agent/ast-engine/internal/callgraph"
	"security-audit-agent/ast-engine/internal/parser"
)

type TaintedVariable struct {
	VariableName  string
	FilePath      string
	Line          int
	QualifiedFunc string
}

type FlowStep struct {
	FilePath string `json:"file"`
	Line     int    `json:"line"`
	Variable string `json:"variable"`
	Kind     string `json:"kind"`
}

type TaintResult struct {
	ReachedSink bool
	FlowPath    []FlowStep
	SinkLine    int
	SinkFile    string
}

type Propagator struct {
	callGraph   *callgraph.CallGraph
	filesByPath map[string]*parser.ParsedFile
}

func NewPropagator(cg *callgraph.CallGraph, files []*parser.ParsedFile) *Propagator {
	filesByPath := make(map[string]*parser.ParsedFile)
	for _, f := range files {
		filesByPath[f.FilePath] = f
	}
	return &Propagator{callGraph: cg, filesByPath: filesByPath}
}

func (p *Propagator) TracePropagation(initial TaintedVariable) TaintResult {
	worklist := []TaintedVariable{initial}
	visited := make(map[string]bool)
	var flowPath []FlowStep

	flowPath = append(flowPath, FlowStep{
		FilePath: initial.FilePath,
		Line:     initial.Line,
		Variable: initial.VariableName,
		Kind:     "source",
	})

	for len(worklist) > 0 {
		current := worklist[0]
		worklist = worklist[1:]

		visitKey := current.FilePath + "|" + current.VariableName + "|" + current.QualifiedFunc
		if visited[visitKey] {
			continue
		}
		visited[visitKey] = true

		file, ok := p.filesByPath[current.FilePath]
		if !ok {
			continue
		}

		// Cek penggunaan variabel di file
		usages := p.findVariableUsages(file, current.VariableName, current.QualifiedFunc)

		for _, usage := range usages {
			// Cek apakah ini sink
			if sinkPattern, isSink := IsSink(usage.calleeQualifiedName); isSink {
				flowPath = append(flowPath, FlowStep{
					FilePath: current.FilePath,
					Line:     usage.line,
					Variable: current.VariableName,
					Kind:     "sink:" + sinkPattern.PatternType,
				})
				return TaintResult{
					ReachedSink: true,
					FlowPath:    flowPath,
					SinkLine:    usage.line,
					SinkFile:    current.FilePath,
				}
			}

			// Jika assignment ke variabel lain
			if usage.kind == "assignment" && usage.targetVariable != "" {
				worklist = append(worklist, TaintedVariable{
					VariableName:  usage.targetVariable,
					FilePath:      current.FilePath,
					Line:          usage.line,
					QualifiedFunc: current.QualifiedFunc,
				})
				flowPath = append(flowPath, FlowStep{
					FilePath: current.FilePath,
					Line:     usage.line,
					Variable: usage.targetVariable,
					Kind:     "assignment",
				})
			}
		}
	}

	return TaintResult{ReachedSink: false, FlowPath: flowPath}
}

type variableUsage struct {
	kind                 string // "assignment" atau "function_call"
	line                 int
	targetVariable       string
	calleeQualifiedName  string
}

func (p *Propagator) findVariableUsages(file *parser.ParsedFile, variableName, qualifiedFunc string) []variableUsage {
	var usages []variableUsage
	lines := file.GetLines()

	for i, line := range lines {
		// Cek assignment: variable = something
		if strings.Contains(line, "=") && strings.Contains(line, variableName) {
			// Cek apakah variabel ada di sisi kanan
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				rightSide := parts[1]
				if strings.Contains(rightSide, variableName) {
					// Ambil target variable dari sisi kiri
					targetVar := strings.TrimSpace(parts[0])
					// Bersihkan dari type hints atau dekorator
					targetVar = strings.Split(targetVar, ":")[0]
					targetVar = strings.TrimSpace(targetVar)

					usages = append(usages, variableUsage{
						kind:           "assignment",
						line:           i + 1,
						targetVariable: targetVar,
					})
				}
			}
		}

		// Cek function call: function(variable)
		if strings.Contains(line, "(") && strings.Contains(line, variableName) {
			// Cari nama fungsi
			re := regexp.MustCompile(`\b(\w+)\s*\(`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				funcName := matches[1]
				// Cek apakah ini sink
				usages = append(usages, variableUsage{
					kind:                "function_call",
					line:                i + 1,
					calleeQualifiedName: funcName,
				})
			}
		}
	}

	return usages
}