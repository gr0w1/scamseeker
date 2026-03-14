import re
from dataclasses import dataclass
from typing import List


WORD_RE = re.compile(r"\w+|\S", re.UNICODE)


@dataclass
class WordContribution:
    start: int
    end: int
    text: str
    contribution: float
    normalized_contribution: float


class ModelExplainabilityService:
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.vectorizer = pipeline.named_steps["tfidf"]
        self.classifier = pipeline.named_steps["clf"]

    def _get_feature_contributions(self, text: str):
        x = self.vectorizer.transform([text])
        feature_names = self.vectorizer.get_feature_names_out()
        coefs = self.classifier.coef_[0]

        row = x[0]
        indices = row.indices
        values = row.data

        contributions = []
        for idx, value in zip(indices, values):
            feature = feature_names[idx]
            contribution = float(value * coefs[idx])
            contributions.append((feature, contribution))

        return contributions

    def _project_to_char_scores(self, text: str, feature_contributions):
        char_scores = [0.0 for _ in text]

        for feature, contribution in feature_contributions:
            raw_feature = feature.strip()
            if not raw_feature:
                continue

            start = 0
            while True:
                pos = text.lower().find(raw_feature.lower(), start)
                if pos == -1:
                    break

                end = pos + len(raw_feature)
                span_len = max(1, end - pos)
                per_char = contribution / span_len

                for i in range(pos, end):
                    if 0 <= i < len(char_scores):
                        char_scores[i] += per_char

                start = pos + 1

        return char_scores

    def explain_words(self, text: str, limit: int = 8, min_contribution: float = 0.0) -> List[dict]:
        feature_contributions = self._get_feature_contributions(text)
        char_scores = self._project_to_char_scores(text, feature_contributions)

        words = []
        for match in WORD_RE.finditer(text):
            start, end = match.span()
            token = text[start:end]

            token_score = sum(char_scores[start:end])
            if token_score <= min_contribution:
                continue

            words.append({
                "start": start,
                "end": end,
                "text": token,
                "contribution": round(float(token_score), 6),
                "normalized_contribution": 0.0,
            })

        if not words:
            return []

        max_abs = max(abs(item["contribution"]) for item in words) or 1.0
        for item in words:
            item["normalized_contribution"] = round(
                min(1.0, abs(item["contribution"]) / max_abs),
                4
            )

        words.sort(key=lambda x: (-x["normalized_contribution"], x["start"]))
        return words[:limit]
