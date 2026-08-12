package parser

import (
	"path/filepath"
	"strings"
)

type SupportedLanguage string

const (
	LanguagePython     SupportedLanguage = "python"
	LanguageJavaScript SupportedLanguage = "javascript"
	LanguageUnknown    SupportedLanguage = "unknown"
)

var extensionToLanguage = map[string]SupportedLanguage{
	".py":  LanguagePython,
	".js":  LanguageJavaScript,
	".jsx": LanguageJavaScript,
}

func DetectLanguage(filePath string) SupportedLanguage {
	ext := strings.ToLower(filepath.Ext(filePath))
	if lang, ok := extensionToLanguage[ext]; ok {
		return lang
	}
	return LanguageUnknown
}