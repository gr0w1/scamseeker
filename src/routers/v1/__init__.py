from fastapi import APIRouter

from src.routers.v1.analysis import analysis_router
from src.routers.v1.health import health_router

v1_router = APIRouter(prefix="/v1")
v1_router.include_router(health_router)
v1_router.include_router(analysis_router)