-- =============================================================================
-- Migration DOWN: 000003_add_llm_verification_and_report_schema
-- =============================================================================

DROP INDEX IF EXISTS idx_vulnerability_report_severity;
DROP INDEX IF EXISTS idx_llm_verifications_finding_id;
DROP INDEX IF EXISTS idx_cve_reference_vuln_type;

DROP TABLE IF EXISTS vulnerability_report;
DROP TABLE IF EXISTS llm_verifications;
DROP TABLE IF EXISTS cve_reference;