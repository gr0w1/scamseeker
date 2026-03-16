from typing import Optional

from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.user import User
from src.repositories.user_repository import UserRepository
from src.configurations.security import create_access_token


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


class AuthService:
    def __init__(self, session: AsyncSession):
        self.repo = UserRepository(session)

    async def register_user(self, *, email: str, first_name: str, last_name: str, password: str) -> User:
        existing = await self.repo.get_by_email(email)
        if existing:
            raise ValueError("Пользователь с таким email уже существует")

        hashed = hash_password(password)
        user = await self.repo.create(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password_hash=hashed,
        )
        return user

    async def authenticate_user(self, email: str, password: str) -> Optional[User]:
        user = await self.repo.get_by_email(email)
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user

    async def create_user_token(self, user: User) -> str:
        return create_access_token(subject=user.id)

