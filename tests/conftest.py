"""Pytest configuration for SecurityScan API tests."""

import pytest
from unittest.mock import patch
from contextlib import asynccontextmanager


# Mock the lifespan to avoid scheduler issues during testing
@asynccontextmanager
async def mock_lifespan(app):
    """Mock lifespan that doesn't start the scheduler."""
    yield


# Apply mock before importing app
@pytest.fixture(scope="session", autouse=True)
def mock_scheduler():
    """Mock the scheduler lifespan for all tests."""
    with patch("app.feeds.scheduler.lifespan", mock_lifespan):
        with patch("app.main.lifespan", mock_lifespan):
            yield
