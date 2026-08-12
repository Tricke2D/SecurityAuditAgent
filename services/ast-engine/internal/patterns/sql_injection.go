package patterns

import (
	"strings"

	"security-audit-agent/ast-engine/internal/parser"
)

type SQLInjectionMatcher struct{}

func NewSQLInjectionMatcher() *SQLInjectionMatcher {
	return &SQLInjectionMatcher{}
}

func (m *SQLInjectionMatcher) Name() string {
	return "sql_injection"
}

func (m *SQLInjectionMatcher) Match(file *parser.ParsedFile) []Finding {
	var findings []Finding

	lines := file.GetLines()

	for i, line := range lines {
		// Skip comment lines
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// DETECT: input() atau request.GET sebagai source
		isSource := strings.Contains(line, "input(") ||
			strings.Contains(line, "request.GET") ||
			strings.Contains(line, "request.POST") ||
			strings.Contains(line, "request.args") ||
			strings.Contains(line, "request.form")

		// DETECT: SQL injection pattern
		hasExecute := strings.Contains(line, "execute") ||
			strings.Contains(line, "executemany") ||
			strings.Contains(line, "query") ||
			strings.Contains(line, "raw")

		// DETECT: concatenation atau f-string
		hasConcat := strings.Contains(line, "+") ||
			strings.Contains(line, "f\"") ||
			strings.Contains(line, "f'") ||
			strings.Contains(line, "%") && strings.Contains(line, "query")

		// Parameterized query (AMAN)
		isParameterized := strings.Contains(line, "?") ||
			strings.Contains(line, "%s") && strings.Contains(line, ",")

		// Jika ada source DAN ada execute/query DAN ada concatenation
		if isSource && hasExecute && hasConcat && !isParameterized {
			findings = append(findings, Finding{
				Line:           i + 1,
				Column:         0,
				PatternType:    "sql_injection",
				RawSeverity:    "high",
				MatchedSnippet: strings.TrimSpace(line),
			})
			continue
		}

		// Jika ada execute/query dengan concatenation (tanpa source)
		if hasExecute && hasConcat && !isParameterized {
			findings = append(findings, Finding{
				Line:           i + 1,
				Column:         0,
				PatternType:    "sql_injection",
				RawSeverity:    "high",
				MatchedSnippet: strings.TrimSpace(line),
			})
		}
	}

	return findings
}