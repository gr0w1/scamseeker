from typing import Optional

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel


class AnalysisCheck(BaseModel):
    __tablename__ = "analysis_checks"

    id: Mapped[int] = mapped_column(primary_key=True)

    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    source_text: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    ml_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    rule_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    final_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    dominant_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    short_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    reasons: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    highlights: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    recommendations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    category_breakdown: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    model_version: Mapped[str] = mapped_column(String(128), nullable=False)

    user: Mapped[Optional["User"]] = relationship(back_populates="analysis_checks")