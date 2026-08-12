package callgraph

import (
	"regexp"
	"strings"

	"security-audit-agent/ast-engine/internal/parser"
)

type Builder struct {
	graph     *CallGraph
	resolvers map[string]*SymbolResolver
}

func NewBuilder() *Builder {
	return &Builder{
		graph:     NewCallGraph(),
		resolvers: make(map[string]*SymbolResolver),
	}
}

func (b *Builder) BuildFromFiles(files []*parser.ParsedFile) *CallGraph {
	for _, file := range files {
		b.registerFunctionDefinitions(file)
	}

	for _, file := range files {
		b.registerCallEdges(file)
	}

	return b.graph
}

func (b *Builder) registerFunctionDefinitions(file *parser.ParsedFile) {
	resolver := NewSymbolResolver()
	b.resolvers[file.FilePath] = resolver

	modulePath := FilePathToModulePath(file.FilePath)
	lines := strings.Split(string(file.Source), "\n")

	for lineNum, line := range lines {
		if isFunctionDefinition(line) {
			functionName := extractFunctionName(line)
			if functionName != "" {
				qualifiedName := modulePath + "." + functionName
				b.graph.AddFunction(qualifiedName, file.FilePath, lineNum+1, lineNum+1)
				resolver.AddBinding(functionName, qualifiedName)
			}
		}
	}
}

func (b *Builder) registerCallEdges(file *parser.ParsedFile) {
	modulePath := FilePathToModulePath(file.FilePath)
	lines := strings.Split(string(file.Source), "\n")
	currentFunction := "unknown"

	for _, line := range lines {
		if isFunctionDefinition(line) {
			currentFunction = extractFunctionName(line)
			continue
		}

		callNames := extractCallNames(line)
		for _, callName := range callNames {
			if isBuiltinFunction(callName) {
				continue
			}

			callerQualifiedName := modulePath + "." + currentFunction

			if resolver, ok := b.resolvers[file.FilePath]; ok {
				if qualified, found := resolver.QualifiedNameFor(callName); found {
					b.graph.AddCallEdge(callerQualifiedName, qualified)
					continue
				}
			}

			calleeQualifiedName := modulePath + "." + callName
			b.graph.AddCallEdge(callerQualifiedName, calleeQualifiedName)
		}
	}
}

var funcDefRegex = regexp.MustCompile(`^\s*def\s+(\w+)\s*\(`)
var callRegex = regexp.MustCompile(`\b(\w+)\s*\(`)

func isFunctionDefinition(line string) bool {
	return funcDefRegex.MatchString(line)
}

func extractFunctionName(line string) string {
	matches := funcDefRegex.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractCallNames(line string) []string {
	matches := callRegex.FindAllStringSubmatch(line, -1)
	var names []string
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) > 1 {
			name := match[1]
			if !seen[name] && !isBuiltinFunction(name) {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}

func isBuiltinFunction(name string) bool {
	builtins := map[string]bool{
		"print": true, "len": true, "str": true, "int": true,
		"float": true, "bool": true, "list": true, "dict": true,
		"set": true, "tuple": true, "range": true, "enumerate": true,
		"zip": true, "map": true, "filter": true, "sum": true,
		"min": true, "max": true, "sorted": true, "reversed": true,
		"open": true, "type": true, "isinstance": true,
	}
	return builtins[name]
}