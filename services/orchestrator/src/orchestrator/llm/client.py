import json

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from orchestrator.config import OrchestratorConfig


class OllamaClient:
    def __init__(self, config: OrchestratorConfig):
        self._host = config.ollama_host
        self._model = config.llm_model
        self._timeout = config.llm_timeout_seconds

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def generate_json(self, prompt: str) -> dict:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(
                f"{self._host}/api/generate",
                json={
                    "model": self._model,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0.1},
                },
            )
            response.raise_for_status()
            result = response.json()
            return json.loads(result["response"])