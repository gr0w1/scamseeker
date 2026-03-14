from abc import ABC, abstractmethod
from typing import Optional

from src.services.model_inference import ModelInferenceService
from src.services.model_explainability import ModelExplainabilityService
from src.services.recommendations import build_recommendations
from src.services.rules import analyze_rules
from src.services.scoring import compute_final_score, resolve_risk_level
from src.schemas.analysis import AnalysisResult



class BaseAnalysisService(ABC):
    @abstractmethod
    async def analyze_text(self, text: str, user_id: Optional[int] = None) -> AnalysisResult:
        raise NotImplementedError


class AnalysisService:
    def __init__(self, model_inference_service: ModelInferenceService, model_version: str):
        self.model_inference_service = model_inference_service
        self.model_explainability_service = ModelExplainabilityService(
            pipeline=model_inference_service.model
        )
        self.model_version = model_version


    @staticmethod
    def normalize_text(text: str) -> str:
        return " ".join(text.strip().split())

    @staticmethod
    def build_short_explanation(
        risk_level: str,
        reasons: list[dict],
        dominant_category: str | None,
    ) -> str:
        if not reasons:
            if risk_level == "low":
                return "Явных сильных признаков фишинга или скама не найдено."
            return "Обнаружены отдельные подозрительные признаки, сообщение стоит перепроверить."

        top_titles = [reason["title"].lower() for reason in reasons[:3]]
        joined = ", ".join(top_titles)

        if dominant_category:
            return (
                f"Сообщение выглядит как {dominant_category}: "
                f"обнаружены признаки — {joined}."
            )

        return f"Обнаружены подозрительные признаки: {joined}."

    async def analyze_text(self, text: str) -> AnalysisResult:
        normalized_text = self.normalize_text(text)

        ml_score = self.model_inference_service.predict_score(normalized_text)

        rule_result = analyze_rules(text)
        model_highlights = self.model_explainability_service.explain_words(text)

        reason_codes = [item["code"] for item in rule_result["reasons"]]
        final_score = compute_final_score(
            ml_score=ml_score,
            rule_score=rule_result["rule_score"],
            reason_codes=reason_codes,
        )
        risk_level = resolve_risk_level(final_score)

        short_explanation = self.build_short_explanation(
            risk_level=risk_level,
            reasons=rule_result["reasons"],
            dominant_category=rule_result["dominant_category"],
        )

        recommendations = build_recommendations(
            risk_level=risk_level,
            dominant_category=rule_result["dominant_category"],
            reason_codes=reason_codes,
        )

        return AnalysisResult(
            text=text,
            ml_score=ml_score,
            rule_score=rule_result["rule_score"],
            final_score=final_score,
            risk_level=risk_level,
            dominant_category=rule_result["dominant_category"],
            short_explanation=short_explanation,
            recommendations=recommendations,
            reasons=rule_result["reasons"],
            highlights=rule_result["highlights"],
            model_highlights=model_highlights,
            category_breakdown=rule_result["category_breakdown"],
            model_version=self.model_version,
        )
