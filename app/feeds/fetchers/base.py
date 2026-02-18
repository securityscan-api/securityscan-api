from abc import ABC, abstractmethod
from typing import List, Dict, Any
from datetime import datetime


RELEVANT_KEYWORDS = [
    "llm", "langchain", "openai", "anthropic", "prompt injection",
    "ai agent", "chatgpt", "embedding", "vector database",
    "fastapi", "pydantic", "requests", "httpx", "claude",
    "gpt", "gemini", "mistral", "ollama", "huggingface"
]


class BaseFetcher(ABC):
    """Abstract base class for security feed fetchers."""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.last_sync: datetime | None = None

    @abstractmethod
    async def fetch(self, since: datetime | None = None) -> List[Dict[str, Any]]:
        """Fetch new vulnerabilities since last sync.

        Returns list of dicts with keys:
        - source_id: str (e.g., CVE-2024-1234)
        - title: str
        - description: str
        - severity: str (CRITICAL, HIGH, MEDIUM, LOW)
        - suggested_pattern: str | None
        - suggested_detector: str | None
        """
        pass

    def is_relevant(self, text: str) -> bool:
        """Check if text contains relevant keywords."""
        text_lower = text.lower()
        return any(kw in text_lower for kw in RELEVANT_KEYWORDS)
