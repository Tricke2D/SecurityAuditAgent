// File: services/ast-engine/internal/storage/models.go
//
// Fungsi: Mendefinisikan struct Go yang merepresentasikan tabel-tabel
// di database PostgreSQL. Dipakai untuk mapping hasil query dan
// operasi CRUD di package storage.
package storage

import "time"

// CodebaseFile merepresentasikan tabel codebase_files di PostgreSQL.
// Menyimpan metadata setiap file yang sudah di-scan.
type CodebaseFile struct {
	ID            int64     `db:"id"`
	FilePath      string    `db:"file_path"`
	Language      string    `db:"language"`
	ASTHash       string    `db:"ast_hash"`
	LastScannedAt time.Time `db:"last_scanned_at"`
}

// StaticFinding merepresentasikan tabel static_findings di PostgreSQL.
// Menyimpan hasil mentah dari static pattern matcher (belum difilter).
type StaticFinding struct {
	ID             int64     `db:"id"`
	FileID         int64     `db:"file_id"`
	LineNumber     int       `db:"line_number"`
	ColumnNumber   int       `db:"column_number"`
	PatternType    string    `db:"pattern_type"`
	RawSeverity    string    `db:"raw_severity"`
	MatchedSnippet string    `db:"matched_snippet"`
	CreatedAt      time.Time `db:"created_at"`
}