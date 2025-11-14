# tests/conftest.py
import os
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# fmt: off
from app import database, models  # noqa: E402
from app.main import app, get_password_hash  # noqa: E402 — импортируем хеширование пароля

# fmt: on

os.environ["TESTING"] = "1"


@pytest.fixture(scope="session")
def temp_db():
    """Создаёт временный файл SQLite на время сессии тестов."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    yield db_path
    os.close(db_fd)
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture(scope="session")
def test_engine(temp_db):
    """Создаёт движок для временной БД и инициализирует схему."""
    engine = create_engine(
        f"sqlite:///{temp_db}", connect_args={"check_same_thread": False}
    )
    models.Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(test_engine):
    """Создаёт новую сессию БД для каждого теста с откатом транзакции."""
    connection = test_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    # Добавляем mock-пользователей только если их ещё нет
    if session.query(models.User).count() == 0:
        mock_users = [
            models.User(
                email="bob@test.com",
                full_name="Bob",
                hashed_password=get_password_hash("password"),
                role="user",
            ),
            models.User(
                email="anna@test.com",
                full_name="Anna",
                hashed_password=get_password_hash("password"),
                role="user",
            ),
            models.User(
                email="denis@test.com",
                full_name="Denis",
                hashed_password=get_password_hash("password"),
                role="user",
            ),
            models.User(
                email="vlad@test.com",
                full_name="Vlad",
                hashed_password=get_password_hash("password"),
                role="user",
            ),
            models.User(
                email="tom@test.com",
                full_name="Tom",
                hashed_password=get_password_hash("password"),
                role="user",
            ),
        ]
        session.add_all(mock_users)
        session.commit()

    yield session

    # Откатываем транзакцию после теста — данные не сохраняются
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    """Переопределяет зависимость get_db для использования тестовой сессии."""

    def override_get_db():
        return db_session

    app.dependency_overrides[database.get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
