package callgraph

import (
	"path/filepath"
	"strings"
)

type ImportBinding struct {
	LocalName     string
	QualifiedName string
}

type SymbolResolver struct {
	bindings map[string]string
}

func NewSymbolResolver() *SymbolResolver {
	return &SymbolResolver{bindings: make(map[string]string)}
}

func (r *SymbolResolver) AddBinding(localName, qualifiedName string) {
	r.bindings[localName] = qualifiedName
}

func (r *SymbolResolver) QualifiedNameFor(localName string) (string, bool) {
	qualifiedName, found := r.bindings[localName]
	return qualifiedName, found
}

func FilePathToModulePath(filePath string) string {
	withoutExt := strings.TrimSuffix(filePath, filepath.Ext(filePath))
	return strings.ReplaceAll(withoutExt, string(filepath.Separator), ".")
}