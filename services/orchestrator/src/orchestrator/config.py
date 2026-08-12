import os
from dataclasses import dataclass


@dataclass(frozen=True)
class OrchestratorConfig:
    database_url: str
    ollama_host: str
    llm_model: str
    llm_timeout_seconds: int


def load_config() -> OrchestratorConfig:
    return OrchestratorConfig(
        database_url=os.getenv(
            "DATABASE_URL",
            "postgresql://postgres:postgres@localhost:5432/security_audit",
        ),
        ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        llm_model=os.getenv("LLM_MODEL", "qwen2.5-coder:7b"),
        llm_timeout_seconds=int(os.getenv("LLM_TIMEOUT_SECONDS", "120")),
    )