package python

// #cgo CFLAGS: -I${SRCDIR}/../../tree-sitter-python/src
// #cgo LDFLAGS: -L${SRCDIR}/../../tree-sitter-python -ltree-sitter-python
import "C"