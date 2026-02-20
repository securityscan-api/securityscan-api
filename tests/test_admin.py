"""Tests for admin API endpoints."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
from app.main import app
from app.db.database import Base, engine


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


client = TestClient(app)


def test_admin_endpoints_require_auth():
    """Admin endpoints return 404 without auth (security by obscurity)."""
    response = client.get("/_s/proposals")
    # Returns 404 when admin_secret is not set or auth is missing
    assert response.status_code in (404, 422)


def test_admin_proposals_with_invalid_key():
    """Admin endpoints return 404 for invalid keys (don't reveal endpoint exists)."""
    with patch("app.api.admin.get_settings") as mock_settings:
        mock_settings.return_value.admin_secret = "secret123"
        response = client.get(
            "/_s/proposals",
            headers={"Authorization": "Bearer wrong_key"}
        )
    assert response.status_code == 404


def test_admin_proposals_with_valid_key():
    """Admin proposals endpoint works with valid Bearer token."""
    with patch("app.api.admin.get_settings") as mock_settings:
        mock_settings.return_value.admin_secret = "secret123"
        response = client.get(
            "/_s/proposals",
            headers={"Authorization": "Bearer secret123"}
        )
    assert response.status_code == 200
    data = response.json()
    assert "proposals" in data
    assert "total" in data
    assert "pending_count" in data


def test_admin_sync_logs_endpoint():
    """Admin can get sync logs via Bearer token."""
    with patch("app.api.admin.get_settings") as mock_settings:
        mock_settings.return_value.admin_secret = "secret123"
        response = client.get(
            "/_s/feeds/logs",
            headers={"Authorization": "Bearer secret123"}
        )
    assert response.status_code == 200
    data = response.json()
    assert "logs" in data
