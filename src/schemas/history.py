from datetime import datetime
from typing import List, Dict, Optional

from pydantic import BaseModel, ConfigDict

from src.schemas.analysis import (
    RiskLevel,
    ThreatCategory,
    HighlightItem,
    ModelHighlightItem,
    ReasonItem,
)


class HistoryListItem(BaseModel):
    id: int
    created_at: datetime
    risk_level: RiskLevel
    final_score: float
    short_explanation: str


class HistoryDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime

    text: str
    normalized_text: Optional[str]

    ml_score: float
    rule_score: float
    final_score: float

    risk_level: RiskLevel
    dominant_category: Optional[ThreatCategory]

    short_explanation: str
    recommendations: List[str]

    reasons: List[ReasonItem]
    highlights: List[HighlightItem]
    model_highlights: List[ModelHighlightItem] = []

    category_breakdown: Dict[str, float]
    model_version: str
