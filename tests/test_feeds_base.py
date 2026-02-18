import pytest
from abc import ABC
from app.feeds.fetchers.base import BaseFetcher, RELEVANT_KEYWORDS


def test_base_fetcher_is_abstract():
    """BaseFetcher cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseFetcher()


def test_relevant_keywords_exist():
    """RELEVANT_KEYWORDS contains AI/LLM related terms."""
    assert "llm" in RELEVANT_KEYWORDS
    assert "prompt injection" in RELEVANT_KEYWORDS
    assert "langchain" in RELEVANT_KEYWORDS


def test_base_fetcher_has_fetch_method():
    """BaseFetcher defines abstract fetch method."""
    assert hasattr(BaseFetcher, "fetch")
