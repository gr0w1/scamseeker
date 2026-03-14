from typing import Any


class ModelInferenceService:
    def __init__(self, model: Any):
        self.model = model

    def predict_score(self, text: str) -> float:
        proba = self.model.predict_proba([text])[0][1]
        return round(float(proba), 4)
