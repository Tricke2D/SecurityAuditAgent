package python

// #include <tree-sitter-python/parser.h>
// #include <tree-sitter-python/scanner.h>
import "C"
import "unsafe"

func Language() unsafe.Pointer {
	return unsafe.Pointer(C.tree_sitter_python())
}
