import httpx
from datetime import datetime, timedelta
from typing import List, Dict, Any
from app.feeds.fetchers.base import BaseFetcher


class NVDFetcher(BaseFetcher):
    """Fetches critical CVEs from NVD (National Vulnerability Database)."""

    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RETRY_DELAYS = [5, 30, 120]

    async def fetch(self, since: datetime | None = None) -> List[Dict[str, Any]]:
        """Fetch critical CVEs from NVD API."""
        if since is None:
            since = datetime.utcnow() - timedelta(days=7)

        params = {
            "cvssV3Severity": "CRITICAL",
            "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000"),
        }

        response = await self._make_request(params)
        return self._parse_response(response)

    async def _make_request(self, params: Dict[str, str]) -> Dict[str, Any]:
        """Make request to NVD API with retry logic."""
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        for attempt, delay in enumerate(self.RETRY_DELAYS):
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.get(self.API_URL, params=params, headers=headers)
                    resp.raise_for_status()
                    return resp.json()
            except httpx.HTTPError as e:
                if attempt == len(self.RETRY_DELAYS) - 1:
                    raise
                import asyncio
                await asyncio.sleep(delay)

        return {"vulnerabilities": []}

    def _parse_response(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse NVD API response into proposal format."""
        results = []
        vulnerabilities = response.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            # Get English description
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                ""
            )

            # Skip if not relevant to our domain
            if not self.is_relevant(description) and not self.is_relevant(cve_id):
                continue

            # Get severity
            severity = "HIGH"  # default
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
                severity = cvss.get("baseSeverity", "HIGH")

            results.append({
                "source_id": cve_id,
                "title": f"{cve_id}: {description[:100]}...",
                "description": description,
                "severity": severity,
                "suggested_pattern": None,  # Admin will define
                "suggested_detector": "cve_check",
            })

        return results
