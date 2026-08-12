-- =============================================================================
-- Migration: 000002_add_call_graph_and_taint_schema
-- FASE 2: Call Graph & Taint Analysis
-- =============================================================================

-- Tabel functions
CREATE TABLE IF NOT EXISTS functions (
    id              BIGSERIAL PRIMARY KEY,
    file_id         BIGINT NOT NULL REFERENCES codebase_files(id) ON DELETE CASCADE,
    function_name   TEXT NOT NULL,
    qualified_name  TEXT NOT NULL UNIQUE,
    start_line      INTEGER NOT NULL,
    end_line        INTEGER NOT NULL,
    parameter_names JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_functions_file_id ON functions(file_id);
CREATE INDEX IF NOT EXISTS idx_functions_qualified_name ON functions(qualified_name);

-- Tabel call_edges
CREATE TABLE IF NOT EXISTS call_edges (
    id              BIGSERIAL PRIMARY KEY,
    caller_function_id BIGINT NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    callee_function_id BIGINT NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    call_site_line  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_call_edges_caller ON call_edges(caller_function_id);
CREATE INDEX IF NOT EXISTS idx_call_edges_callee ON call_edges(callee_function_id);

-- Tabel taint_flows
CREATE TABLE IF NOT EXISTS taint_flows (
    id                  BIGSERIAL PRIMARY KEY,
    source_finding_id   BIGINT NOT NULL REFERENCES static_findings(id) ON DELETE CASCADE,
    sink_finding_id     BIGINT NOT NULL REFERENCES static_findings(id) ON DELETE CASCADE,
    flow_path           JSONB NOT NULL,
    is_sanitized        BOOLEAN NOT NULL DEFAULT false,
    sanitization_detail TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_taint_flows_source ON taint_flows(source_finding_id);
CREATE INDEX IF NOT EXISTS idx_taint_flows_sink ON taint_flows(sink_finding_id);
CREATE INDEX IF NOT EXISTS idx_taint_flows_is_sanitized ON taint_flows(is_sanitized);