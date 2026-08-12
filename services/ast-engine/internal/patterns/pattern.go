package patterns

import (
	"security-audit-agent/ast-engine/internal/parser"
)

type Finding struct {
	Line           int
	Column         int
	PatternType    string
	RawSeverity    string
	MatchedSnippet string
}

type PatternMatcher interface {
	Name() string
	Match(file *parser.ParsedFile) []Finding
}