package parser

type Node struct {
	Type      string
	StartLine int
	StartCol  int
	EndLine   int
	EndCol    int
	Text      string
}

type NodeVisitor func(node *Node) bool

func WalkAST(root *Node, visitor NodeVisitor) {
	if root == nil {
		return
	}
}

func FindNodesByType(root *Node, nodeType string) []*Node {
	return []*Node{}
}

func LineColumnOf(node *Node) (line int, column int) {
	return node.StartLine, node.StartCol
}

func GetNodeContent(node *Node, source []byte) string {
	return node.Text
}