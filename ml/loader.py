from pathlib import Path
from typing import Any

import joblib


class ModelLoader:
    def __init__(self, model_path: str | Path):
        self.model_path = Path(model_path)
        self._model: Any = None

    def load(self) -> Any:
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"ML model file not found: {self.model_path}"
            )

        if self._model is None:
            self._model = joblib.load(self.model_path)

        return self._model

    @property
    def model(self) -> Any:
        if self._model is None:
            raise RuntimeError("ML model is not loaded")
        return self._model