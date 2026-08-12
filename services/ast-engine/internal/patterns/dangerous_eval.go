package patterns

import (
	"regexp"
	"strings"

	"security-audit-agent/ast-engine/internal/parser"
)

type DangerousEvalMatcher struct{}

func NewDangerousEvalMatcher() *DangerousEvalMatcher {
	return &DangerousEvalMatcher{}
}

func (m *DangerousEvalMatcher) Name() string {
	return "dangerous_eval"
}

func (m *DangerousEvalMatcher) Match(file *parser.ParsedFile) []Finding {
	var findings []Finding

	evalPattern := regexp.MustCompile(`\b(eval|exec)\s*\(`)
	lines := strings.Split(string(file.Source), "\n")

	for i, line := range lines {
		if evalPattern.MatchString(line) {
			findings = append(findings, Finding{
				Line:           i + 1,
				Column:         0,
				PatternType:    m.Name(),
				RawSeverity:    "critical",
				MatchedSnippet: strings.TrimSpace(line),
			})
		}
	}

	return findings
}