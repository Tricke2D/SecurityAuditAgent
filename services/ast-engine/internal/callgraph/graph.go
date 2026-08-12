package callgraph

import (
	"gonum.org/v1/gonum/graph/simple"
)

type FunctionNode struct {
	id            int64
	QualifiedName string
	FilePath      string
	StartLine     int
	EndLine       int
}

func (n FunctionNode) ID() int64 { return n.id }

type CallGraph struct {
	graph        *simple.DirectedGraph
	nameToNodeID map[string]int64
	nextID       int64
}

func NewCallGraph() *CallGraph {
	return &CallGraph{
		graph:        simple.NewDirectedGraph(),
		nameToNodeID: make(map[string]int64),
		nextID:       0,
	}
}

func (cg *CallGraph) AddFunction(qualifiedName, filePath string, startLine, endLine int) FunctionNode {
	if existingID, found := cg.nameToNodeID[qualifiedName]; found {
		existingNode := cg.graph.Node(existingID)
		return existingNode.(FunctionNode)
	}

	node := FunctionNode{
		id:            cg.nextID,
		QualifiedName: qualifiedName,
		FilePath:      filePath,
		StartLine:     startLine,
		EndLine:       endLine,
	}
	cg.graph.AddNode(node)
	cg.nameToNodeID[qualifiedName] = node.id
	cg.nextID++
	return node
}

func (cg *CallGraph) AddCallEdge(callerQualifiedName, calleeQualifiedName string) {
	// Cegah self edge
	if callerQualifiedName == calleeQualifiedName {
		return
	}

	callerID, callerFound := cg.nameToNodeID[callerQualifiedName]
	calleeID, calleeFound := cg.nameToNodeID[calleeQualifiedName]
	if !callerFound || !calleeFound {
		return
	}
	cg.graph.SetEdge(cg.graph.NewEdge(cg.graph.Node(callerID), cg.graph.Node(calleeID)))
}

func (cg *CallGraph) CalleesOf(qualifiedName string) []FunctionNode {
	nodeID, found := cg.nameToNodeID[qualifiedName]
	if !found {
		return nil
	}

	var callees []FunctionNode
	iterator := cg.graph.From(nodeID)
	for iterator.Next() {
		callees = append(callees, iterator.Node().(FunctionNode))
	}
	return callees
}

func (cg *CallGraph) CallersOf(qualifiedName string) []FunctionNode {
	nodeID, found := cg.nameToNodeID[qualifiedName]
	if !found {
		return nil
	}

	var callers []FunctionNode
	iterator := cg.graph.To(nodeID)
	for iterator.Next() {
		callers = append(callers, iterator.Node().(FunctionNode))
	}
	return callers
}

func (cg *CallGraph) AllNodes() []FunctionNode {
	var nodes []FunctionNode
	iterator := cg.graph.Nodes()
	for iterator.Next() {
		nodes = append(nodes, iterator.Node().(FunctionNode))
	}
	return nodes
}

func (cg *CallGraph) GetFunctionNode(qualifiedName string) (FunctionNode, bool) {
	nodeID, found := cg.nameToNodeID[qualifiedName]
	if !found {
		return FunctionNode{}, false
	}
	node := cg.graph.Node(nodeID)
	return node.(FunctionNode), true
}

func (cg *CallGraph) HasFunction(qualifiedName string) bool {
	_, found := cg.nameToNodeID[qualifiedName]
	return found
}

func (cg *CallGraph) NodeCount() int {
	return cg.graph.Nodes().Len()
}

func (cg *CallGraph) EdgeCount() int {
	return cg.graph.Edges().Len()
}