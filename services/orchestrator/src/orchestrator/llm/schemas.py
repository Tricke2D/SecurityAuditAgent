from pydantic import BaseModel, Field


class ExploitabilityVerdict(BaseModel):
    is_exploitable: bool = Field(description="True jika vulnerability bisa dieksploitasi")
    confidence: float = Field(ge=0.0, le=1.0, description="Keyakinan LLM 0.0-1.0")
    false_positive: bool = Field(description="True jika sebenarnya aman")
    reasoning: str = Field(description="Penjelasan lengkap")
    attack_scenario: str = Field(default="", description="Skenario exploit konkret")