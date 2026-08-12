package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"

	"security-audit-agent/ast-engine/internal/parser"
	"security-audit-agent/ast-engine/internal/patterns"
)

type FileScanResult struct {
	FilePath string
	Language string
	ASTHash  string
	Findings []patterns.Finding
}

type Scanner struct {
	matchers []patterns.PatternMatcher
}

func NewScanner(matchers []patterns.PatternMatcher) *Scanner {
	return &Scanner{matchers: matchers}
}

func (s *Scanner) ScanDirectory(rootPath string) ([]FileScanResult, error) {
	var results []FileScanResult

	err := filepath.WalkDir(rootPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		lang := parser.DetectLanguage(path)
		if lang == parser.LanguageUnknown {
			return nil
		}

		result, scanErr := s.scanFile(path)
		if scanErr != nil {
			fmt.Printf("warning: failed to scan %s: %v\n", path, scanErr)
			return nil
		}

		results = append(results, *result)
		return nil
	})

	return results, err
}

func (s *Scanner) scanFile(path string) (*FileScanResult, error) {
	parsedFile, err := parser.ParseFile(path)
	if err != nil {
		return nil, err
	}

	var allFindings []patterns.Finding
	for _, matcher := range s.matchers {
		findings := matcher.Match(parsedFile)
		allFindings = append(allFindings, findings...)
	}

	hash := sha256.Sum256(parsedFile.Source)

	return &FileScanResult{
		FilePath: path,
		Language: string(parsedFile.Language),
		ASTHash:  hex.EncodeToString(hash[:]),
		Findings: allFindings,
	}, nil
}