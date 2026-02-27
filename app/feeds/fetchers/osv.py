"""OSV.dev fetcher — vulnerabilities in PyPI and npm packages used by AI skills."""

import asyncio
import logging
import httpx
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from app.feeds.fetchers.base import BaseFetcher

logger = logging.getLogger(__name__)


class OSVFetcher(BaseFetcher):
    """Fetches vulnerabilities from OSV.dev for packages commonly used in AI agent skills."""

    API_URL = "https://api.osv.dev/v1/query"
    RETRY_DELAYS = [5, 30, 120]
    MAX_CONCURRENT = 5  # Limit parallel requests to OSV

    # Packages commonly imported in AI agent skills
    WATCHED_PACKAGES: Dict[str, List[str]] = {
        "PyPI": [
            "langchain", "langchain-core", "langchain-community", "langchain-openai",
            "openai", "anthropic", "litellm", "llama-index", "llama-index-core",
            "fastapi", "requests", "httpx", "aiohttp", "pydantic",
            "transformers", "sentence-transformers", "torch",
            "chromadb", "pinecone-client", "weaviate-client",
            "boto3", "paramiko", "cryptography", "pyOpenSSL",
        ],
        "npm": [
            "openai", "@anthropic-ai/sdk", "@anthropic-ai/claude-code",
            "langchain", "@langchain/core", "@langchain/community",
            "@modelcontextprotocol/sdk",
            "axios", "node-fetch", "got", "express",
        ],
    }

    async def fetch(self, since: datetime | None = None) -> List[Dict[str, Any]]:
        """Fetch recent vulnerabilities for AI-relevant packages."""
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=7)

        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)
        results: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=30) as client:
            tasks = [
                self._query_package(client, semaphore, ecosystem, package, since)
                for ecosystem, packages in self.WATCHED_PACKAGES.items()
                for package in packages
            ]
            batches = await asyncio.gather(*tasks, return_exceptions=True)

        for batch in batches:
            if isinstance(batch, list):
                results.extend(batch)

        return results

    async def _query_package(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        ecosystem: str,
        package: str,
        since: datetime,
    ) -> List[Dict[str, Any]]:
        """Query OSV for vulnerabilities in a single package."""
        async with semaphore:
            for attempt, delay in enumerate(self.RETRY_DELAYS):
                try:
                    resp = await client.post(
                        self.API_URL,
                        json={"package": {"name": package, "ecosystem": ecosystem}},
                    )
                    resp.raise_for_status()
                    vulns = resp.json().get("vulns", [])
                    return self._parse_vulns(vulns, package, ecosystem, since)
                except httpx.HTTPError as e:
                    logger.warning(f"OSV attempt {attempt + 1} failed for {package}: {e}")
                    if attempt == len(self.RETRY_DELAYS) - 1:
                        return []
                    await asyncio.sleep(delay)
        return []

    def _parse_vulns(
        self,
        vulns: List[Dict],
        package: str,
        ecosystem: str,
        since: datetime,
    ) -> List[Dict[str, Any]]:
        """Parse OSV vulnerability list into proposal format."""
        results = []
        for vuln in vulns:
            # Skip old entries
            modified_str = vuln.get("modified", "")
            if modified_str:
                try:
                    modified = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
                    if modified < since:
                        continue
                except ValueError:
                    pass

            osv_id = vuln.get("id", "")
            summary = vuln.get("summary", f"Vulnerability in {package}")
            details = vuln.get("details", summary)
            severity = self._extract_severity(vuln)

            # Summarize affected versions
            version_parts = []
            for affected in vuln.get("affected", []):
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "introduced" in event:
                            version_parts.append(f">={event['introduced']}")
                        if "fixed" in event:
                            version_parts.append(f"fixed in {event['fixed']}")
            version_info = ", ".join(version_parts[:4]) or "check advisory"

            results.append({
                "source_id": osv_id,
                "title": f"{osv_id}: {package} ({ecosystem}) — {summary[:80]}",
                "description": (
                    f"{details}\n\n"
                    f"Package: {package} ({ecosystem})\n"
                    f"Affected versions: {version_info}"
                ),
                "severity": severity,
                "suggested_pattern": package.replace("-", "_").replace("/", "_"),
                "suggested_detector": "dependency_check",
            })

        return results

    def _extract_severity(self, vuln: Dict) -> str:
        """Extract severity from OSV data (database_specific → aliases → default)."""
        db_specific = vuln.get("database_specific", {})
        sev = db_specific.get("severity", "").upper()
        if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return sev

        # CVE alias → assume HIGH
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                return "HIGH"

        return "MEDIUM"
