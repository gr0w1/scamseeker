from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from src.configurations.settings import settings
from src.models.base import BaseModel

engine: AsyncEngine = create_async_engine(
    url=settings.database_url,
    echo=settings.db_echo,
    pool_pre_ping=True,
)

AsyncSessionFactory = async_sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_db_and_tables() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(BaseModel.metadata.create_all)