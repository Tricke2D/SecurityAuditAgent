package patterns

import (
	"regexp"
	"strings"

	"security-audit-agent/ast-engine/internal/parser"
)

type InsecureDeserializeMatcher struct{}

func NewInsecureDeserializeMatcher() *InsecureDeserializeMatcher {
	return &InsecureDeserializeMatcher{}
}

func (m *InsecureDeserializeMatcher) Name() string {
	return "insecure_deserialization"
}

func (m *InsecureDeserializeMatcher) Match(file *parser.ParsedFile) []Finding {
	var findings []Finding

	deserializePattern := regexp.MustCompile(`(pickle\.loads?|yaml\.load)\s*\(`)
	lines := strings.Split(string(file.Source), "\n")

	for i, line := range lines {
		if deserializePattern.MatchString(line) {
			// Skip kalau ada SafeLoader untuk yaml
			if strings.Contains(line, "yaml.load") && strings.Contains(line, "SafeLoader") {
				continue
			}
			findings = append(findings, Finding{
				Line:           i + 1,
				Column:         0,
				PatternType:    m.Name(),
				RawSeverity:    "high",
				MatchedSnippet: strings.TrimSpace(line),
			})
		}
	}

	return findings
}