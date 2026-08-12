import asyncio
from pathlib import Path

from orchestrator.config import load_config
from orchestrator.db.connection import Database
from orchestrator.db.repository import VerificationRepository
from orchestrator.llm.client import OllamaClient
from orchestrator.llm.verifier import Verifier


async def main():
    config = load_config()
    db = Database(config)
    repo = VerificationRepository(db)
    client = OllamaClient(config)

    print("=== FASE 3: LLM Verification ===")
    print(f"Model: {config.llm_model}")
    print(f"Ollama: {config.ollama_host}")

    pending = repo.fetch_unverified_taint_flows()
    print(f"Pending verification: {len(pending)} flows")

    if len(pending) == 0:
        print("✅ No pending flows to verify")
        return

    verifier = Verifier(client, repo, Path.cwd(), config.llm_model)
    verdicts = await verifier.verify_all_pending()

    print(f"\n✅ Verified {len(verdicts)} flows")


if __name__ == "__main__":
    asyncio.run(main())