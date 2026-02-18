import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from app.feeds.fetchers.nvd import NVDFetcher


@pytest.fixture
def nvd_fetcher():
    return NVDFetcher()


def test_nvd_fetcher_inherits_base():
    """NVDFetcher extends BaseFetcher."""
    from app.feeds.fetchers.base import BaseFetcher
    assert issubclass(NVDFetcher, BaseFetcher)


def test_nvd_fetcher_has_api_url():
    """NVDFetcher has correct API URL."""
    fetcher = NVDFetcher()
    assert "nvd.nist.gov" in fetcher.API_URL


@pytest.mark.asyncio
async def test_nvd_fetcher_parses_cve_response():
    """NVDFetcher correctly parses NVD API response."""
    mock_response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "LLM prompt injection vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]
                    }
                }
            }
        ]
    }

    fetcher = NVDFetcher()
    with patch.object(fetcher, "_make_request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = mock_response
        results = await fetcher.fetch()

    assert len(results) == 1
    assert results[0]["source_id"] == "CVE-2024-1234"
    assert results[0]["severity"] == "CRITICAL"
