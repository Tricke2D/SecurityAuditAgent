package patterns

import (
	"regexp"
	"strings"

	"security-audit-agent/ast-engine/internal/parser"
)

type HardcodedSecretMatcher struct{}

func NewHardcodedSecretMatcher() *HardcodedSecretMatcher {
	return &HardcodedSecretMatcher{}
}

func (m *HardcodedSecretMatcher) Name() string {
	return "hardcoded_secret"
}

func (m *HardcodedSecretMatcher) Match(file *parser.ParsedFile) []Finding {
	var findings []Finding

	secretPattern := regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*=\s*["'][^"']+["']`)
	lines := strings.Split(string(file.Source), "\n")

	for i, line := range lines {
		if secretPattern.MatchString(line) {
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