from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from src.configurations.settings import settings
from src.configurations.database import get_async_session
from src.models.user import User
from src.repositories.user_repository import UserRepository
from src.schemas.auth import TokenPayload

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

ALGORITHM = settings.jwt_alg


def create_access_token(subject: int, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta is None:
        expires_delta = timedelta(seconds=settings.jwt_ttl_seconds)

    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {"sub": str(subject), "exp": expire}
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_async_session),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось подтвердить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[ALGORITHM])
        token_data = TokenPayload(**payload)
    except JWTError:
        raise credentials_exception

    if token_data.sub is None:
        raise credentials_exception

    repo = UserRepository(session)
    user = await repo.get_by_id(int(token_data.sub))
    if user is None:
        raise credentials_exception

    return user
async def get_current_user_optional(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
) -> Optional[User]:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None

    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None

    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[ALGORITHM])
        token_data = TokenPayload(**payload)
    except JWTError:
        return None

    if token_data.sub is None:
        return None

    repo = UserRepository(session)
    user = await repo.get_by_id(int(token_data.sub))
    return user
