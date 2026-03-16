from typing import Optional, List, Dict, Literal

from pydantic import BaseModel, Field, ConfigDict


RiskLevel = Literal["low", "medium", "high"]
SeverityLevel = Literal["low", "medium", "high"]
ThreatCategory = Literal["phishing", "scam", "spam", "social_engineering", "financial"]


class AnalyzeTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000)


class HighlightItem(BaseModel):
    start: int = Field(..., ge=0)
    end: int = Field(..., ge=0)
    text: str
    score: float = Field(..., ge=0.0, le=1.0)
    label: str
    reason_code: str
    severity: SeverityLevel
    category: ThreatCategory


class ModelHighlightItem(BaseModel):
    start: int = Field(..., ge=0)
    end: int = Field(..., ge=0)
    text: str
    contribution: float
    normalized_contribution: float = Field(..., ge=0.0, le=1.0)


class ReasonItem(BaseModel):
    code: str
    title: str
    description: str
    category: ThreatCategory
    severity: SeverityLevel
    weight: float = Field(..., ge=0.0, le=1.0)


class AnalysisResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    text: str

    ml_score: float = Field(..., ge=0.0, le=1.0)
    rule_score: float = Field(..., ge=0.0, le=1.0)
    final_score: float = Field(..., ge=0.0, le=1.0)

    risk_level: RiskLevel
    dominant_category: Optional[ThreatCategory] = None

    short_explanation: str
    recommendations: List[str]

    reasons: List[ReasonItem]
    highlights: List[HighlightItem]
    model_highlights: List[ModelHighlightItem] = []

    category_breakdown: Dict[str, float]
    model_version: str