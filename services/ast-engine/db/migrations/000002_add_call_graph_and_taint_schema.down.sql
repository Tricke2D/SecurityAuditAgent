-- =============================================================================
-- Migration DOWN: 000002_add_call_graph_and_taint_schema
-- =============================================================================

DROP INDEX IF EXISTS idx_taint_flows_is_sanitized;
DROP INDEX IF EXISTS idx_taint_flows_sink;
DROP INDEX IF EXISTS idx_taint_flows_source;
DROP INDEX IF EXISTS idx_call_edges_callee;
DROP INDEX IF EXISTS idx_call_edges_caller;
DROP INDEX IF EXISTS idx_functions_qualified_name;
DROP INDEX IF EXISTS idx_functions_file_id;

DROP TABLE IF EXISTS taint_flows;
DROP TABLE IF EXISTS call_edges;
DROP TABLE IF EXISTS functions;