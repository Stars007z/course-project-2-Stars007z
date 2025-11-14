import os
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

import bcrypt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, OAuth2PasswordBearer
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from . import database, models, schemas

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

load_dotenv()
# Конфигурация JWT
SECRET_KEY = os.getenv("SECRET_KEY")
security = HTTPBearer()
# if not SECRET_KEY:
#     raise RuntimeError("SECRET_KEY is required. Set it in .env or environment.")

ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))


app = FastAPI(title="Feature Votes", version="0.1.0")


limiter = Limiter(
    key_func=get_remote_address, enabled=not os.getenv("TESTING", "").lower() == "true"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

models.Base.metadata.create_all(bind=database.engine)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    return user


def require_role(required_role: str):
    def role_checker(current_user: models.User = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return role_checker


class ApiError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        self.code = code
        self.message = message
        self.status = status


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError):
    # Генерируем уникальный ID для трассировки
    correlation_id = str(uuid4())

    # Стандартный URI типа ошибки
    error_type = f"https://featurevotes.example.com/errors/{exc.code}"

    # Сопоставление кодов с человекочитаемыми заголовками (title)
    title_map = {
        "email_exists": "Email already registered",
        "invalid_credentials": "Invalid credentials",
        "not_found": "Resource not found",
        "feature_not_found": "Feature not found",
        "duplicate_vote": "Duplicate vote",
    }
    title = title_map.get(exc.code, "Request error")

    # Формируем RFC 7807-совместимый ответ
    rfc7807_payload = {
        "type": error_type,
        "title": title,
        "status": exc.status,
        "detail": exc.message,
        "correlation_id": correlation_id,
    }

    return JSONResponse(
        status_code=exc.status,
        content=rfc7807_payload,
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    correlation_id = str(uuid4())

    # Определяем тип ошибки по статусу или детали
    status_to_title = {
        401: "Unauthorized",
        403: "Forbidden",
        404: "Resource not found",
        422: "Validation error",
        429: "Too Many Requests",
    }
    title = status_to_title.get(exc.status_code, "HTTP error")
    detail = str(exc.detail) if exc.detail else title

    error_type = f"https://featurevotes.example.com/errors/http_{exc.status_code}"

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "type": error_type,
            "title": title,
            "status": exc.status_code,
            "detail": detail,
            "correlation_id": correlation_id,
        },
    )


def init_mock_data(db: Session):
    if db.query(models.User).count() == 0:
        mock_users = [
            models.User(
                email="bob@example.com",
                full_name="Bob",
                hashed_password=get_password_hash("password"),
                role="user",
            ),
            models.User(
                email="anna@example.com",
                full_name="Anna",
                hashed_password=get_password_hash("password"),
                role="user",
            ),
            models.User(
                email="denis@example.com",
                full_name="Denis",
                hashed_password=get_password_hash("password"),
                role="user",
            ),
        ]
        db.add_all(mock_users)
        db.commit()


@app.on_event("startup")
def startup_event():
    db = database.SessionLocal()
    try:
        init_mock_data(db)
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


# --- Аутентификация ---


@app.post("/users", response_model=schemas.UserOut)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = get_user_by_email(db, user.email)
    if db_user:
        raise ApiError(
            code="email_exists",
            message="Проверьте почту, если адрес подтверждён",
            status=400,
        )
    hashed_pw = get_password_hash(user.password)
    new_user = models.User(
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_pw,
        role="user",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/auth/login", response_model=schemas.Token)
def login_for_access_token(
    user: schemas.UserLogin, db: Session = Depends(database.get_db)  # ← изменено здесь
):
    db_user = get_user_by_email(db, user.email)
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise ApiError(
            code="invalid_credentials", message="Неверные данные аккаунта", status=401
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(db_user.id)}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# --- Пользователь ---


@app.get("/users/me", response_model=schemas.UserOut)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user


@app.put("/users/me", response_model=schemas.UserOut)
def update_user_me(
    user_update: schemas.UserUpdate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    current_user.full_name = user_update.full_name
    db.commit()
    db.refresh(current_user)
    return current_user


# --- Фичи (Features) ---


@app.get("/features/top", response_model=list[schemas.FeatureOut])
def top_features(db: Session = Depends(database.get_db)):
    return (
        db.query(models.Feature)
        .order_by(models.Feature.vote_count.desc())
        .limit(3)
        .all()
    )


@app.get("/features", response_model=list[schemas.FeatureOut])
def list_features(db: Session = Depends(database.get_db)):
    return db.query(models.Feature).all()


@app.get("/features/{feature_id}", response_model=schemas.FeatureOut)
def get_feature(feature_id: int, db: Session = Depends(database.get_db)):
    feature = db.query(models.Feature).filter(models.Feature.id == feature_id).first()
    if not feature:
        raise ApiError(code="not_found", message="Feature not found", status=404)
    return feature


@app.post("/features", response_model=schemas.FeatureOut)
def create_feature(
    feature: schemas.FeatureCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    db_feature = models.Feature(
        title=feature.title, description=feature.description, owner_id=current_user.id
    )
    db.add(db_feature)
    db.commit()
    db.refresh(db_feature)
    return db_feature


@app.put("/features/{feature_id}", response_model=schemas.FeatureOut)
def update_feature(
    feature_id: int,
    feature: schemas.FeatureCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    db_feature = (
        db.query(models.Feature).filter(models.Feature.id == feature_id).first()
    )
    if not db_feature:
        raise ApiError(code="not_found", message="Feature not found", status=404)
    if db_feature.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your feature")
    db_feature.title = feature.title
    db_feature.description = feature.description
    db.commit()
    db.refresh(db_feature)
    return db_feature


@app.delete("/features/{feature_id}")
def delete_feature(
    feature_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    db_feature = (
        db.query(models.Feature).filter(models.Feature.id == feature_id).first()
    )
    if not db_feature:
        raise ApiError(code="not_found", message="Feature not found", status=404)
    if db_feature.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your feature")
    db.delete(db_feature)
    db.commit()
    return {"ok": True}


# --- Голосование ---


@app.post("/features/{feature_id}/vote")
def vote_feature(
    feature_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    feature = db.query(models.Feature).filter(models.Feature.id == feature_id).first()
    if not feature:
        raise ApiError(
            code="feature_not_found", message="Feature not found", status=404
        )

    existing_vote = (
        db.query(models.Vote)
        .filter(
            models.Vote.feature_id == feature_id, models.Vote.user_id == current_user.id
        )
        .first()
    )
    if existing_vote:
        raise ApiError(
            code="duplicate_vote",
            message="User has already voted for this feature",
            status=409,
        )

    new_vote = models.Vote(feature_id=feature_id, user_id=current_user.id)
    db.add(new_vote)
    feature.vote_count += 1
    db.commit()
    return {
        "message": "Vote registered",
        "feature_id": feature_id,
        "user_id": current_user.id,
    }
