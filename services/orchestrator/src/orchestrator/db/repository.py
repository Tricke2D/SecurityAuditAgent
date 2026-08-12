from dataclasses import dataclass

from orchestrator.db.connection import Database


@dataclass
class UnverifiedTaintFlow:
    taint_flow_id: int
    source_finding_id: int
    sink_finding_id: int
    flow_path: list[dict]
    source_file_path: str
    source_line: int
    sink_file_path: str
    sink_line: int
    sink_pattern_type: str
    sink_snippet: str


class VerificationRepository:
    def __init__(self, db: Database):
        self._db = db

    def fetch_unverified_taint_flows(self) -> list[UnverifiedTaintFlow]:
        query = """
            SELECT
                tf.id AS taint_flow_id,
                tf.source_finding_id,
                tf.sink_finding_id,
                tf.flow_path,
                src_cf.file_path AS source_file_path,
                src_sf.line_number AS source_line,
                sink_cf.file_path AS sink_file_path,
                sink_sf.line_number AS sink_line,
                sink_sf.pattern_type AS sink_pattern_type,
                sink_sf.matched_snippet AS sink_snippet
            FROM taint_flows tf
            JOIN static_findings src_sf ON src_sf.id = tf.source_finding_id
            JOIN codebase_files src_cf ON src_cf.id = src_sf.file_id
            JOIN static_findings sink_sf ON sink_sf.id = tf.sink_finding_id
            JOIN codebase_files sink_cf ON sink_cf.id = sink_sf.file_id
            LEFT JOIN llm_verifications lv ON lv.taint_flow_id = tf.id
            WHERE tf.is_sanitized = false AND lv.id IS NULL
        """
        with self._db.connection() as conn:
            rows = conn.execute(query).fetchall()

        return [
            UnverifiedTaintFlow(
                taint_flow_id=row[0],
                source_finding_id=row[1],
                sink_finding_id=row[2],
                flow_path=row[3],
                source_file_path=row[4],
                source_line=row[5],
                sink_file_path=row[6],
                sink_line=row[7],
                sink_pattern_type=row[8],
                sink_snippet=row[9],
            )
            for row in rows
        ]

    def save_verification(
        self,
        finding_id: int,
        taint_flow_id: int,
        is_exploitable: bool,
        confidence: float,
        reasoning_trace: str,
        false_positive: bool,
        model_used: str,
    ) -> None:
        query = """
            INSERT INTO llm_verifications
                (finding_id, taint_flow_id, is_exploitable, confidence,
                 reasoning_trace, false_positive_bool, model_used)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        with self._db.connection() as conn:
            conn.execute(
                query,
                (finding_id, taint_flow_id, is_exploitable, confidence,
                 reasoning_trace, false_positive, model_used),
            )
            conn.commit()