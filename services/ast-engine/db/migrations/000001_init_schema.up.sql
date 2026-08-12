-- =============================================================================
-- Migration: 000001_init_schema
-- Tujuan: Membuat skema awal untuk menyimpan hasil scan codebase dan
--         temuan static analysis (raw findings, sebelum taint analysis
--         dan LLM verification di fase berikutnya).
-- =============================================================================

-- Tabel codebase_files: metadata setiap file yang sudah di-scan.
-- ast_hash dipakai untuk skip re-parsing file yang tidak berubah
-- (incremental scan di masa depan).
CREATE TABLE codebase_files (
    id              BIGSERIAL PRIMARY KEY,
    file_path       TEXT NOT NULL UNIQUE,
    language        TEXT NOT NULL,          -- 'python', 'javascript', dst
    ast_hash        TEXT NOT NULL,          -- SHA-256 dari isi file, untuk cache invalidation
    last_scanned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Tabel static_findings: hasil mentah dari pattern matcher.
-- Ini BELUM final — masih banyak kemungkinan false positive,
-- akan difilter oleh taint analysis (Fase 2) dan LLM verification (Fase 3).
CREATE TABLE static_findings (
    id              BIGSERIAL PRIMARY KEY,
    file_id         BIGINT NOT NULL REFERENCES codebase_files(id) ON DELETE CASCADE,
    line_number     INTEGER NOT NULL,
    column_number   INTEGER NOT NULL,
    pattern_type    TEXT NOT NULL,          -- 'sql_injection', 'hardcoded_secret', dst
    raw_severity    TEXT NOT NULL,          -- 'low', 'medium', 'high', 'critical' (heuristik awal)
    matched_snippet TEXT NOT NULL,          -- Potongan kode yang match, untuk audit trail
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index untuk query findings per file (dipakai terus-menerus saat generate report)
CREATE INDEX idx_static_findings_file_id ON static_findings(file_id);

-- Index untuk filter/group by pattern_type di dashboard nanti
CREATE INDEX idx_static_findings_pattern_type ON static_findings(pattern_type);