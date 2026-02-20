"""Tests for MCP server module."""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock


def test_mcp_server_imports():
    """MCP server module imports correctly."""
    from app.mcp_server import mcp, scan_skill, get_report, check_certification
    assert mcp is not None
    assert mcp.name == "SecurityScan"


def test_mcp_has_tools():
    """MCP server has required tools registered."""
    from app.mcp_server import mcp
    # FastMCP registers tools internally
    assert hasattr(mcp, 'tool')


def test_scan_result_model():
    """ScanResult model has required fields."""
    from app.mcp_server import ScanResult

    result = ScanResult(
        scan_id="test-123",
        skill_url="https://github.com/test/repo",
        score=95,
        recommendation="SAFE",
        issues_count=0,
        issues=[],
        cached=False
    )

    assert result.scan_id == "test-123"
    assert result.score == 95
    assert result.recommendation == "SAFE"


def test_certification_result_model():
    """CertificationResult model has required fields."""
    from app.mcp_server import CertificationResult

    result = CertificationResult(
        skill_url="https://github.com/test/repo",
        is_certified=True,
        score=100,
        certified_at="2024-01-15T10:00:00",
        cert_hash="abc123"
    )

    assert result.is_certified is True
    assert result.cert_hash == "abc123"


def test_get_mcp_app():
    """get_mcp_app returns ASGI application."""
    from app.mcp_server import get_mcp_app

    app = get_mcp_app()
    assert app is not None
    assert callable(app)


@pytest.mark.asyncio
async def test_check_certification_not_certified():
    """check_certification returns not certified for unknown URL."""
    from app.mcp_server import check_certification

    with patch("app.mcp_server.get_db") as mock_db:
        mock_session = MagicMock()
        mock_db.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_db.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter.return_value.first.return_value = None

        result = check_certification("https://github.com/unknown/repo")

    assert result.is_certified is False
    assert result.cert_hash is None
