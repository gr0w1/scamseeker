from fastapi import APIRouter

from src.configurations.settings import settings
from src.services.rules import RULES

info_router = APIRouter(prefix="/info", tags=["info"])


@info_router.get("/model")
async def model_info():
    return {
        "model_version": settings.model_version,
        "description": "Модель для оценки риска фишинговых и мошеннических сообщений",
    }


@info_router.get("/rules")
async def rules_info():
    return [
        {
            "code": rule.code,
            "title": rule.title,
            "description": rule.description,
            "category": rule.category,
            "severity": rule.severity,
        }
        for rule in RULES
    ]
