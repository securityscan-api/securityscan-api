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


# Scan endpoint tests

def test_scan_requires_auth():
    response = client.post("/scan", json={
        "skill_url": "https://github.com/octocat/Hello-World"
    })
    assert response.status_code == 422  # Missing X-API-Key header


def test_scan_with_invalid_api_key():
    response = client.post(
        "/scan",
        json={"skill_url": "https://github.com/octocat/Hello-World"},
        headers={"X-API-Key": "invalid_key"}
    )
    assert response.status_code == 401


def test_scan_with_valid_auth():
    # Register first
    reg_response = client.post("/auth/register", json={"email": "scanner@example.com"})
    api_key = reg_response.json()["api_key"]

    # Scan
    response = client.post(
        "/scan",
        json={"skill_url": "https://github.com/octocat/Hello-World"},
        headers={"X-API-Key": api_key}
    )
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert "score" in data
    assert "recommendation" in data
    assert data["cached"] == False
    assert data["scans_remaining"] == 4  # Started with 5, used 1


def test_scan_returns_cached():
    # Register
    reg_response = client.post("/auth/register", json={"email": "cache@example.com"})
    api_key = reg_response.json()["api_key"]

    # First scan
    response1 = client.post(
        "/scan",
        json={"skill_url": "https://github.com/octocat/Hello-World"},
        headers={"X-API-Key": api_key}
    )
    assert response1.json()["cached"] == False

    # Second scan (same URL - should be cached)
    response2 = client.post(
        "/scan",
        json={"skill_url": "https://github.com/octocat/Hello-World"},
        headers={"X-API-Key": api_key}
    )
    assert response2.json()["cached"] == True
    # Cached scan shouldn't count against limit
    assert response2.json()["scans_remaining"] == 4


def test_get_scan_by_id():
    # Register and scan
    reg_response = client.post("/auth/register", json={"email": "getbyid@example.com"})
    api_key = reg_response.json()["api_key"]

    scan_response = client.post(
        "/scan",
        json={"skill_url": "https://github.com/octocat/Hello-World"},
        headers={"X-API-Key": api_key}
    )
    scan_id = scan_response.json()["scan_id"]

    # Get by ID
    response = client.get(
        f"/scan/{scan_id}",
        headers={"X-API-Key": api_key}
    )
    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id


def test_get_scan_not_found():
    reg_response = client.post("/auth/register", json={"email": "notfound@example.com"})
    api_key = reg_response.json()["api_key"]

    response = client.get(
        "/scan/nonexistent-id",
        headers={"X-API-Key": api_key}
    )
    assert response.status_code == 404
