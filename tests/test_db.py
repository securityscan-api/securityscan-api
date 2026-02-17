import pytest
from app.db.database import engine, SessionLocal
from app.db.models import Base, User


def test_database_creates_tables():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    assert db is not None
    db.close()


def test_user_model_exists():
    user = User(
        email="test@example.com",
        api_key_hash="hashed_key",
        plan="FREE"
    )
    assert user.email == "test@example.com"
    assert user.plan == "FREE"
