import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import Base, engine


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "SkillShield API" in response.json()["service"]


def test_register_user():
    response = client.post("/auth/register", json={
        "email": "test@example.com"
    })
    assert response.status_code == 201
    data = response.json()
    assert "api_key" in data
    assert data["api_key"].startswith("ss_live_")
    assert data["plan"] == "FREE"
    assert data["scans_remaining"] == 5


def test_register_duplicate_email():
    client.post("/auth/register", json={"email": "dupe@example.com"})
    response = client.post("/auth/register", json={"email": "dupe@example.com"})
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"]


def test_register_invalid_plan():
    response = client.post("/auth/register", json={
        "email": "invalid@example.com",
        "plan": "INVALID"
    })
    assert response.status_code == 400


def test_docs_available():
    response = client.get("/docs")
    assert response.status_code == 200
