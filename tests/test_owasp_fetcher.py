import pytest
from datetime import datetime
from unittest.mock import AsyncMock, patch
from app.feeds.fetchers.owasp_llm import OWASPLLMFetcher


def test_owasp_fetcher_inherits_base():
    """OWASPLLMFetcher extends BaseFetcher."""
    from app.feeds.fetchers.base import BaseFetcher
    assert issubclass(OWASPLLMFetcher, BaseFetcher)


def test_owasp_fetcher_has_github_config():
    """OWASPLLMFetcher has GitHub repo configuration."""
    fetcher = OWASPLLMFetcher()
    assert fetcher.REPO_OWNER == "OWASP"
    assert "llm" in fetcher.REPO_NAME.lower()


@pytest.mark.asyncio
async def test_owasp_fetcher_detects_new_commits():
    """OWASPLLMFetcher creates proposals for new commits."""
    mock_commits = [
        {
            "sha": "abc123",
            "commit": {
                "message": "Update LLM01 Prompt Injection guidance",
                "committer": {"date": "2024-01-15T10:00:00Z"}
            }
        }
    ]

    fetcher = OWASPLLMFetcher()
    with patch.object(fetcher, "_get_commits", new_callable=AsyncMock) as mock:
        mock.return_value = mock_commits
        results = await fetcher.fetch()

    assert len(results) >= 1
    assert "OWASP" in results[0]["source_id"]
