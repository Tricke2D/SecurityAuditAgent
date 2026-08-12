#!/usr/bin/env python3
"""
Tree-sitter AST Parser Service
Menerima file path, mengembalikan AST nodes dalam format JSON
"""

import sys
import json
import os
from tree_sitter import Language, Parser
from tree_sitter_python import language as python_language
from tree_sitter_javascript import language as javascript_language

class ASTParser:
    def __init__(self):
        self.parsers = {
            '.py': self._create_parser(python_language()),
            '.js': self._create_parser(javascript_language()),
            '.jsx': self._create_parser(javascript_language()),
        }
    
    def _create_parser(self, language):
        parser = Parser()
        parser.set_language(language)
        return parser
    
    def parse_file(self, file_path):
        """Parse file dan return AST nodes"""
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.parsers:
            return None
        
        with open(file_path, 'rb') as f:
            source = f.read()
        
        parser = self.parsers[ext]
        tree = parser.parse(source)
        
        # Ekstrak nodes
        nodes = []
        self._extract_nodes(tree.root_node, nodes)
        
        return {
            'file_path': file_path,
            'nodes': nodes,
            'source': source.decode('utf-8', errors='ignore')
        }
    
    def _extract_nodes(self, node, nodes, depth=0):
        """Ekstrak semua node dengan posisi"""
        if depth > 10:  # Limit depth untuk performance
            return
        
        nodes.append({
            'type': node.type,
            'start_line': node.start_point[0] + 1,
            'start_col': node.start_point[1] + 1,
            'end_line': node.end_point[0] + 1,
            'end_col': node.end_point[1] + 1,
            'text': node.text.decode('utf-8', errors='ignore')[:500]  # Limit text length
        })
        
        for child in node.children:
            self._extract_nodes(child, nodes, depth + 1)

def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'No file path provided'}))
        sys.exit(1)
    
    file_path = sys.argv[1]
    parser = ASTParser()
    result = parser.parse_file(file_path)
    
    if result is None:
        print(json.dumps({'error': 'Unsupported file type'}))
        sys.exit(1)
    
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()