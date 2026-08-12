package javascript

// #include <tree-sitter-javascript/parser.h>
// #include <tree-sitter-javascript/scanner.h>
import "C"
import "unsafe"

func Language() unsafe.Pointer {
	return unsafe.Pointer(C.tree_sitter_javascript())
}
