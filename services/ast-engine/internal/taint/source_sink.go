package taint

type SourcePattern struct {
	QualifiedNameSuffix string
	Description         string
}

type SinkPattern struct {
	QualifiedNameSuffix string
	PatternType         string
	Description         string
}

var KnownSources = []SourcePattern{
	{QualifiedNameSuffix: "request.GET", Description: "Django/Flask query parameter"},
	{QualifiedNameSuffix: "request.POST", Description: "Django/Flask form data"},
	{QualifiedNameSuffix: "request.args", Description: "Flask query parameter"},
	{QualifiedNameSuffix: "request.form", Description: "Flask form data"},
	{QualifiedNameSuffix: "request.json", Description: "Flask/FastAPI JSON body"},
	{QualifiedNameSuffix: "input", Description: "Python built-in input()"},
}

var KnownSinks = []SinkPattern{
	{QualifiedNameSuffix: "execute", PatternType: "sql_injection", Description: "Eksekusi query SQL"},
	{QualifiedNameSuffix: "executemany", PatternType: "sql_injection", Description: "Eksekusi batch query SQL"},
	{QualifiedNameSuffix: "eval", PatternType: "dangerous_eval", Description: "Eksekusi string sebagai kode"},
	{QualifiedNameSuffix: "exec", PatternType: "dangerous_eval", Description: "Eksekusi string sebagai kode"},
	{QualifiedNameSuffix: "os.system", PatternType: "command_injection", Description: "Eksekusi shell command"},
	{QualifiedNameSuffix: "pickle.loads", PatternType: "insecure_deserialization", Description: "Deserialisasi data"},
}

func IsSource(qualifiedName string) (SourcePattern, bool) {
	for _, pattern := range KnownSources {
		if hasSuffix(qualifiedName, pattern.QualifiedNameSuffix) {
			return pattern, true
		}
	}
	return SourcePattern{}, false
}

func IsSink(qualifiedName string) (SinkPattern, bool) {
	for _, pattern := range KnownSinks {
		if hasSuffix(qualifiedName, pattern.QualifiedNameSuffix) {
			return pattern, true
		}
	}
	return SinkPattern{}, false
}

func hasSuffix(full, suffix string) bool {
	if len(full) < len(suffix) {
		return false
	}
	return full[len(full)-len(suffix):] == suffix
}