import asyncio
import logging
import httpx
from datetime import datetime
from typing import List, Dict, Any
from app.feeds.fetchers.base import BaseFetcher

logger = logging.getLogger(__name__)


class OWASPLLMFetcher(BaseFetcher):
    """Fetches updates from OWASP LLM Top 10 GitHub repository."""

    REPO_OWNER = "OWASP"
    REPO_NAME = "www-project-llm-top-10"
    API_BASE = "https://api.github.com"
    RETRY_DELAYS = [5, 30, 120]  # Exponential backoff

    # Mapping of OWASP LLM categories to severity
    SEVERITY_MAP = {
        "LLM01": "CRITICAL",  # Prompt Injection
        "LLM02": "HIGH",      # Insecure Output Handling
        "LLM03": "HIGH",      # Training Data Poisoning
        "LLM04": "CRITICAL",  # Model Denial of Service
        "LLM05": "HIGH",      # Supply Chain Vulnerabilities
        "LLM06": "MEDIUM",    # Sensitive Information Disclosure
        "LLM07": "HIGH",      # Insecure Plugin Design
        "LLM08": "MEDIUM",    # Excessive Agency
        "LLM09": "HIGH",      # Overreliance
        "LLM10": "MEDIUM",    # Model Theft
    }

    async def fetch(self, since: datetime | None = None) -> List[Dict[str, Any]]:
        """Fetch recent commits from OWASP LLM Top 10 repo."""
        commits = await self._get_commits(since)
        return self._parse_commits(commits)

    async def _get_commits(self, since: datetime | None) -> List[Dict[str, Any]]:
        """Get commits from GitHub API with retry logic."""
        url = f"{self.API_BASE}/repos/{self.REPO_OWNER}/{self.REPO_NAME}/commits"
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.api_key:
            headers["Authorization"] = f"token {self.api_key}"

        params = {"per_page": 30}
        if since:
            params["since"] = since.isoformat()

        for attempt, delay in enumerate(self.RETRY_DELAYS):
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.get(url, headers=headers, params=params)
                    resp.raise_for_status()
                    return resp.json()
            except httpx.HTTPError as e:
                logger.warning(f"OWASP fetch attempt {attempt + 1} failed: {e}")
                if attempt == len(self.RETRY_DELAYS) - 1:
                    logger.error(f"OWASP fetch failed after {len(self.RETRY_DELAYS)} attempts")
                    return []
                await asyncio.sleep(delay)

        return []

    def _parse_commits(self, commits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse commits into proposal format."""
        results = []

        for commit in commits:
            message = commit.get("commit", {}).get("message", "")
            sha = commit.get("sha", "")[:7]

            # Look for LLM category mentions in commit message
            for category, severity in self.SEVERITY_MAP.items():
                if category.lower() in message.lower() or category in message:
                    source_id = f"OWASP-{category}-{sha}"
                    results.append({
                        "source_id": source_id,
                        "title": f"OWASP LLM Top 10 Update: {category}",
                        "description": f"Commit: {message}\n\nThis update may contain new guidance for {category} vulnerabilities.",
                        "severity": severity,
                        "suggested_pattern": None,
                        "suggested_detector": self._get_detector_for_category(category),
                    })
                    break  # One proposal per commit

        return results

    def _get_detector_for_category(self, category: str) -> str:
        """Map OWASP category to detector type."""
        mapping = {
            "LLM01": "prompt_injection",
            "LLM02": "output_validation",
            "LLM03": "data_poisoning",
            "LLM04": "dos_protection",
            "LLM05": "dependency_check",
            "LLM06": "exfiltration",
            "LLM07": "plugin_security",
            "LLM08": "privilege_escalation",
            "LLM09": "overreliance_check",
            "LLM10": "model_protection",
        }
        return mapping.get(category, "general")
