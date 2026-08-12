-- =============================================================================
-- Migration DOWN: 000001_init_schema
-- Tujuan: Rollback skema awal — menghapus semua tabel yang dibuat
--         di migration UP.
-- =============================================================================

DROP INDEX IF EXISTS idx_static_findings_pattern_type;
DROP INDEX IF EXISTS idx_static_findings_file_id;
DROP TABLE IF EXISTS static_findings;
DROP TABLE IF EXISTS codebase_files;