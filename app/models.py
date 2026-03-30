from pydantic import BaseModel, Field
from typing import Optional


class AnalyzeRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)
    check_breach: bool = Field(default=False, description="check HIBP for breaches")


class AnalyzeResponse(BaseModel):
    score: int = Field(..., ge=0, le=100)
    label: str
    entropy_bits: float
    crack_time_display: str
    suggestions: list[str]
    breached: Optional[bool] = None
    breach_count: Optional[int] = None


class GenerateRequest(BaseModel):
    length: int = Field(default=16, ge=8, le=128)
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = Field(
        default=False,
        description="exclude chars like 0/O, 1/l/I that look similar"
    )


class GenerateResponse(BaseModel):
    password: str
    score: int
    entropy_bits: float


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
