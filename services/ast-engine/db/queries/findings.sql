-- =============================================================================
-- File: db/queries/findings.sql
-- Tujuan: Query SQL untuk sqlc generate — menghasilkan kode Go type-safe
--         untuk operasi CRUD di package storage.
-- =============================================================================

-- name: UpsertCodebaseFile :one
INSERT INTO codebase_files (file_path, language, ast_hash, last_scanned_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (file_path)
DO UPDATE SET ast_hash = EXCLUDED.ast_hash, last_scanned_at = now()
RETURNING id;

-- name: DeleteFindingsByFileID :exec
DELETE FROM static_findings WHERE file_id = $1;

-- name: InsertFinding :exec
INSERT INTO static_findings
    (file_id, line_number, column_number, pattern_type, raw_severity, matched_snippet)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetAllFindings :many
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
    cf.file_path;