from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from pydantic import ValidationError

from orchestrator.db.repository import UnverifiedTaintFlow, VerificationRepository
from orchestrator.llm.client import OllamaClient
from orchestrator.llm.schemas import ExploitabilityVerdict

PROMPT_DIR = Path(__file__).parent / "prompts"


class Verifier:
    def __init__(self, llm_client: OllamaClient, repository: VerificationRepository,
                 codebase_root: Path, model_name: str):
        self._llm_client = llm_client
        self._repository = repository
        self._codebase_root = codebase_root
        self._model_name = model_name
        self._jinja_env = Environment(loader=FileSystemLoader(PROMPT_DIR))

    async def verify_all_pending(self) -> list[ExploitabilityVerdict]:
        pending = self._repository.fetch_unverified_taint_flows()
        verdicts = []

        print(f"Found {len(pending)} pending flows to verify")

        for flow in pending:
            print(f"Verifying taint_flow_id={flow.taint_flow_id}...")
            verdict = await self._verify_single_flow(flow)
            if verdict is not None:
                verdicts.append(verdict)
                print(f"  ✅ Verified: exploitable={verdict.is_exploitable}, confidence={verdict.confidence}")
            else:
                print(f"  ❌ Failed to verify")

        return verdicts

    async def _verify_single_flow(self, flow: UnverifiedTaintFlow) -> ExploitabilityVerdict | None:
        relevant_files = self._gather_relevant_file_contents(flow)

        prompt = self._jinja_env.get_template("verify_exploitability.j2").render(
            source_file=flow.source_file_path,
            source_line=flow.source_line,
            sink_file=flow.sink_file_path,
            sink_line=flow.sink_line,
            sink_pattern_type=flow.sink_pattern_type,
            sink_snippet=flow.sink_snippet,
            flow_path=flow.flow_path,
            relevant_file_contents=relevant_files,
        )

        try:
            raw_response = await self._llm_client.generate_json(prompt)
            verdict = ExploitabilityVerdict.model_validate(raw_response)
        except (ValidationError, Exception) as error:
            print(f"warning: gagal verifikasi taint_flow_id={flow.taint_flow_id}: {error}")
            return None

        self._repository.save_verification(
            finding_id=flow.sink_finding_id,
            taint_flow_id=flow.taint_flow_id,
            is_exploitable=verdict.is_exploitable,
            confidence=verdict.confidence,
            reasoning_trace=verdict.reasoning,
            false_positive=verdict.false_positive,
            model_used=self._model_name,
        )

        return verdict

    def _gather_relevant_file_contents(self, flow: UnverifiedTaintFlow) -> list[dict]:
        unique_file_paths = {step["file"] for step in flow.flow_path}
        unique_file_paths.add(flow.source_file_path)
        unique_file_paths.add(flow.sink_file_path)

        contents = []
        for file_path in sorted(unique_file_paths):
            full_path = self._codebase_root / file_path
            if full_path.exists():
                contents.append({
                    "file_path": file_path,
                    "code": full_path.read_text(encoding="utf-8"),
                })
        return contents