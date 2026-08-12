package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ParsedFile struct {
	Source   []byte
	Language SupportedLanguage
	FilePath string
}

func ParseFile(filePath string) (*ParsedFile, error) {
	lang := DetectLanguage(filePath)
	if lang == LanguageUnknown {
		return nil, fmt.Errorf("unsupported file extension for: %s", filePath)
	}

	source, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	return &ParsedFile{
		Source:   source,
		Language: lang,
		FilePath: filePath,
	}, nil
}

func (f *ParsedFile) GetLines() []string {
	return strings.Split(string(f.Source), "\n")
}

// ParseDirectory membaca semua file yang didukung dalam folder
func ParseDirectory(rootPath string) ([]*ParsedFile, error) {
	var files []*ParsedFile

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		lang := DetectLanguage(path)
		if lang == LanguageUnknown {
			return nil
		}

		file, err := ParseFile(path)
		if err != nil {
			return nil
		}

		files = append(files, file)
		return nil
	})

	return files, err
}