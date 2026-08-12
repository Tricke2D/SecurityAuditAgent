-- =============================================================================
-- Migration: 000003_add_llm_verification_and_report_schema
-- FASE 3: LLM Verification, Severity Scoring & Testing
-- =============================================================================

-- Tabel cve_reference: local CVE database
CREATE TABLE IF NOT EXISTS cve_reference (
    id              BIGSERIAL PRIMARY KEY,
    cve_id          TEXT NOT NULL UNIQUE,
    vulnerability_type TEXT NOT NULL,
    description     TEXT NOT NULL,
    cvss_score      NUMERIC(3,1),
    keywords        TEXT[] NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_cve_reference_vuln_type ON cve_reference(vulnerability_type);

-- Tabel llm_verifications: hasil LLM reasoning
CREATE TABLE IF NOT EXISTS llm_verifications (
    id                  BIGSERIAL PRIMARY KEY,
    finding_id          BIGINT NOT NULL REFERENCES static_findings(id) ON DELETE CASCADE,
    taint_flow_id       BIGINT REFERENCES taint_flows(id) ON DELETE SET NULL,
    is_exploitable      BOOLEAN NOT NULL,
    confidence          NUMERIC(3,2) NOT NULL,
    reasoning_trace     TEXT NOT NULL,
    false_positive_bool BOOLEAN NOT NULL DEFAULT false,
    model_used          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_llm_verifications_finding_id ON llm_verifications(finding_id);

-- Tabel vulnerability_report: final report
CREATE TABLE IF NOT EXISTS vulnerability_report (
    id                       BIGSERIAL PRIMARY KEY,
    finding_id               BIGINT NOT NULL REFERENCES static_findings(id) ON DELETE CASCADE,
    severity_final           TEXT NOT NULL,
    severity_score_numeric   NUMERIC(3,1) NOT NULL,
    cve_reference            TEXT,
    remediation_suggestion   TEXT NOT NULL,
    generated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vulnerability_report_severity ON vulnerability_report(severity_score_numeric DESC);