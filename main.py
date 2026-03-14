from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import ORJSONResponse

import src.models  # noqa: F401
from src.configurations.database import create_db_and_tables
from src.configurations.settings import settings
from src.ml.loader import ModelLoader
from src.routers import api_router
from src.services.analysis import AnalysisService
from src.services.model_inference import ModelInferenceService


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_db_and_tables()

    model_path = Path("src/ml/artifacts/spam_lr_char3-5_tfidf.joblib")
    loader = ModelLoader(model_path=model_path)
    model = loader.load()

    model_inference_service = ModelInferenceService(model=model)
    analysis_service = AnalysisService(
        model_inference_service=model_inference_service,
        model_version=settings.model_version,
    )

    app.state.model_loader = loader
    app.state.analysis_service = analysis_service

    yield


app = FastAPI(
    title=settings.app_title,
    description=settings.app_description,
    version=settings.app_version,
    debug=settings.debug,
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
)

app.include_router(api_router)


@app.get("/", include_in_schema=False)
async def root():
    return {"message": "Text Risk Analyzer API is running"}