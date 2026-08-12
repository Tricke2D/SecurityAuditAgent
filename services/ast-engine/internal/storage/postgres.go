// File: services/ast-engine/internal/storage/postgres.go
//
// Fungsi: Mengelola koneksi ke PostgreSQL dan menyediakan fungsi untuk
// menyimpan hasil scan (codebase_files + static_findings) ke database.
// Menggunakan transaction supaya penyimpanan satu file dan semua
// finding-nya bersifat atomic (semua berhasil atau semua batal).
package storage

import (
	"context"
	"database/sql"
	"fmt"

	"security-audit-agent/ast-engine/internal/scanner"

	_ "github.com/lib/pq"
)

// Store membungkus koneksi database dan menyediakan method-method
// persistence yang dipakai oleh CLI command.
type Store struct {
	db *sql.DB
}

// NewStore membuka koneksi ke PostgreSQL menggunakan connection string
// yang diberikan (biasanya dari environment variable DATABASE_URL).
func NewStore(connectionString string) (*Store, error) {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	return &Store{db: db}, nil
}

// SaveScanResult menyimpan satu FileScanResult ke database: upsert baris
// di codebase_files (update jika file_path sudah ada, insert jika belum),
// lalu insert semua finding terkait. Dijalankan dalam satu transaction
// supaya konsisten — kalau proses insert findings gagal di tengah jalan,
// seluruh perubahan untuk file ini di-rollback.
func (s *Store) SaveScanResult(ctx context.Context, result scanner.FileScanResult) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // no-op jika sudah di-Commit

	var fileID int64
	upsertQuery := `
		INSERT INTO codebase_files (file_path, language, ast_hash, last_scanned_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (file_path)
		DO UPDATE SET ast_hash = EXCLUDED.ast_hash, last_scanned_at = now()
		RETURNING id
	`
	err = tx.QueryRowContext(ctx, upsertQuery, result.FilePath, result.Language, result.ASTHash).Scan(&fileID)
	if err != nil {
		return fmt.Errorf("failed to upsert codebase_files: %w", err)
	}

	// Hapus finding lama untuk file ini sebelum insert yang baru,
	// supaya re-scan tidak menumpuk duplikat finding dari hasil lama.
	_, err = tx.ExecContext(ctx, `DELETE FROM static_findings WHERE file_id = $1`, fileID)
	if err != nil {
		return fmt.Errorf("failed to clear old findings: %w", err)
	}

	insertFindingQuery := `
		INSERT INTO static_findings
			(file_id, line_number, column_number, pattern_type, raw_severity, matched_snippet)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	for _, finding := range result.Findings {
		_, err = tx.ExecContext(ctx, insertFindingQuery,
			fileID, finding.Line, finding.Column, finding.PatternType,
			finding.RawSeverity, finding.MatchedSnippet)
		if err != nil {
			return fmt.Errorf("failed to insert finding: %w", err)
		}
	}

	return tx.Commit()
}

// FindingSummary dipakai untuk menghasilkan report ringkas dari CLI,
// menggabungkan data dari codebase_files dan static_findings.
type FindingSummary struct {
	FilePath       string
	LineNumber     int
	PatternType    string
	RawSeverity    string
	MatchedSnippet string
}

// GetAllFindings mengambil seluruh finding yang tersimpan di database,
// diurutkan berdasarkan severity (critical dulu) lalu file path — dipakai
// oleh CLI `report` command untuk menampilkan hasil scan ke user.
func (s *Store) GetAllFindings(ctx context.Context) ([]FindingSummary, error) {
	query := `
		SELECT cf.file_path, sf.line_number, sf.pattern_type, sf.raw_severity, sf.matched_snippet
		FROM static_findings sf
		JOIN codebase_files cf ON cf.id = sf.file_id
		ORDER BY
			CASE sf.raw_severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				ELSE 4
			END,
			cf.file_path
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var summaries []FindingSummary
	for rows.Next() {
		var summary FindingSummary
		if err := rows.Scan(&summary.FilePath, &summary.LineNumber, &summary.PatternType,
			&summary.RawSeverity, &summary.MatchedSnippet); err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}
		summaries = append(summaries, summary)
	}
	return summaries, rows.Err()
}

// GetDB mengembalikan koneksi database untuk keperluan query langsung
func (s *Store) GetDB() *sql.DB {
    return s.db
}