"""GitHub Advisory Database fetcher — security advisories for pip and npm packages."""

import asyncio
import logging
import httpx
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from app.feeds.fetchers.base import BaseFetcher

logger = logging.getLogger(__name__)


class GitHubAdvisoryFetcher(BaseFetcher):
    """Fetches security advisories from GitHub Advisory Database (GHSA)."""

    API_URL = "https://api.github.com/advisories"
    RETRY_DELAYS = [5, 30, 120]

    async def fetch(self, since: datetime | None = None) -> List[Dict[str, Any]]:
        """Fetch critical/high advisories for pip and npm ecosystems."""
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=7)

        results: List[Dict[str, Any]] = []
        for ecosystem in ("pip", "npm"):
            for severity in ("critical", "high"):
                advisories = await self._fetch_ecosystem(ecosystem, severity, since)
                results.extend(advisories)

        return results

    async def _fetch_ecosystem(
        self,
        ecosystem: str,
        severity: str,
        since: datetime,
    ) -> List[Dict[str, Any]]:
        """Fetch advisories for one ecosystem."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.api_key:
            headers["Authorization"] = f"token {self.api_key}"

        params = {
            "ecosystem": ecosystem,
            "severity": severity,
            "per_page": 100,
            "published": f">={since.strftime('%Y-%m-%d')}",
        }

        for attempt, delay in enumerate(self.RETRY_DELAYS):
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.get(self.API_URL, headers=headers, params=params)
                    resp.raise_for_status()
                    advisories = resp.json()
                    return [
                        self._parse_advisory(a)
                        for a in advisories
                        if self._is_relevant(a)
                    ]
            except httpx.HTTPError as e:
                logger.warning(
                    f"GitHub Advisory attempt {attempt + 1} failed for {ecosystem}: {e}"
                )
                if attempt == len(self.RETRY_DELAYS) - 1:
                    logger.error(f"GitHub Advisory fetch failed for {ecosystem} after retries")
                    return []
                await asyncio.sleep(delay)

        return []

    def _is_relevant(self, advisory: Dict) -> bool:
        """Return True if the advisory touches an AI-relevant package."""
        for vuln in advisory.get("vulnerabilities", []):
            pkg_name = vuln.get("package", {}).get("name", "")
            if self.is_relevant(pkg_name):
                return True
        summary = advisory.get("summary", "")
        description = advisory.get("description", "")
        return self.is_relevant(summary) or self.is_relevant(description)

    def _parse_advisory(self, advisory: Dict) -> Dict[str, Any]:
        """Convert GitHub advisory to proposal format."""
        ghsa_id = advisory.get("ghsa_id", "")
        summary = advisory.get("summary", "")
        description = advisory.get("description", summary)
        raw_severity = advisory.get("severity", "high").upper()
        severity = raw_severity if raw_severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH"

        # Collect affected package info
        package_lines = []
        first_package = None
        for vuln in advisory.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            name = pkg.get("name", "")
            ecosystem = pkg.get("ecosystem", "")
            fixed = (
                vuln.get("first_patched_version") if isinstance(vuln.get("first_patched_version"), str) else None
                or "no fix available"
            )
            if name:
                if first_package is None:
                    first_package = name
                package_lines.append(f"  {name} ({ecosystem}) → fix: {fixed}")

        cve_id = advisory.get("cve_id") or "N/A"
        packages_str = "\n".join(package_lines) or "  see advisory"

        return {
            "source_id": ghsa_id,
            "title": f"{ghsa_id}: {summary[:100]}",
            "description": (
                f"{description}\n\n"
                f"Affected packages:\n{packages_str}\n"
                f"CVE: {cve_id}"
            ),
            "severity": severity,
            "suggested_pattern": first_package,
            "suggested_detector": "dependency_check",
        }
