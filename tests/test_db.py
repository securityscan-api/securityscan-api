import pytest
import hashlib
from app.db.database import engine, SessionLocal, Base
from app.db.models import User
from app.db.crud import create_user, get_user_by_api_key, create_scan, get_cached_scan


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()
    Base.metadata.drop_all(bind=engine)


def test_create_user(db_session):
    user = create_user(db_session, "test@example.com")
    assert user.email == "test@example.com"
    assert user.plan == "FREE"
    assert user.api_key_hash is not None


def test_get_user_by_api_key(db_session):
    user = create_user(db_session, "lookup@example.com")
    found = get_user_by_api_key(db_session, user._raw_api_key)
    assert found is not None
    assert found.email == "lookup@example.com"


def test_create_scan(db_session):
    user = create_user(db_session, "scanner@example.com")
    scan = create_scan(
        db_session,
        user_id=user.id,
        skill_url="https://github.com/test/skill",
        score=85,
        recommendation="SAFE",
        issues=[],
        scan_time_ms=1234
    )
    assert scan.score == 85
    assert scan.recommendation == "SAFE"


def test_get_cached_scan_returns_recent(db_session):
    user = create_user(db_session, "cache@example.com")
    create_scan(
        db_session,
        user_id=user.id,
        skill_url="https://github.com/cached/skill",
        score=90,
        recommendation="SAFE",
        issues=[],
        scan_time_ms=500
    )
    cached = get_cached_scan(db_session, "https://github.com/cached/skill")
    assert cached is not None
    assert cached.score == 90
