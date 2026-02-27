from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.feeds.fetchers.nvd import NVDFetcher
from app.feeds.fetchers.owasp_llm import OWASPLLMFetcher
from app.feeds.fetchers.osv import OSVFetcher
from app.feeds.fetchers.github_advisory import GitHubAdvisoryFetcher
from app.feeds.proposal import ProposalGenerator
from app.db.database import get_db_context
from app.db.models import FeedSyncLog
from app.config import get_settings


class FeedMonitor:
    """Orchestrates security feed fetching and proposal generation."""

    def __init__(self):
        settings = get_settings()
        self.nvd_fetcher = NVDFetcher(api_key=settings.nvd_api_key)
        self.owasp_fetcher = OWASPLLMFetcher(api_key=settings.github_token)
        self.osv_fetcher = OSVFetcher()
        self.github_advisory_fetcher = GitHubAdvisoryFetcher(api_key=settings.github_token)
        self.proposal_generator = ProposalGenerator()

    async def sync_all(self) -> Dict[str, Any]:
        """Run feed synchronization for all sources."""
        return await self.run_sync("all")

    async def run_sync(self, source: str = "all") -> Dict[str, Any]:
        """Run feed synchronization.

        Args:
            source: "all", "nvd", or "owasp_llm"

        Returns:
            Dict with sync results
        """
        results = {
            "started_at": datetime.now(timezone.utc),
            "total_proposals": 0,
            "sources": {},
            "errors": {},
        }

        if source in ("all", "nvd"):
            await self._sync_source("NVD", self.nvd_fetcher, results)

        if source in ("all", "owasp_llm"):
            await self._sync_source("OWASP_LLM", self.owasp_fetcher, results)

        if source in ("all", "osv"):
            await self._sync_source("OSV", self.osv_fetcher, results)

        if source in ("all", "github_advisory"):
            await self._sync_source("GITHUB_ADVISORY", self.github_advisory_fetcher, results)

        results["completed_at"] = datetime.now(timezone.utc)
        return results

    async def _sync_source(
        self,
        source_name: str,
        fetcher,
        results: Dict[str, Any]
    ) -> None:
        """Sync a single source and update results."""
        started_at = datetime.now(timezone.utc)

        try:
            data = await fetcher.fetch()
            created = self.proposal_generator.create_proposals_batch(source_name, data)

            results["sources"][source_name] = {
                "fetched": len(data),
                "created": created,
            }
            results["total_proposals"] += len(data)

            self._log_sync(source_name, "SUCCESS", created, None, started_at)

        except Exception as e:
            results["errors"][source_name] = str(e)
            self._log_sync(source_name, "FAILED", 0, str(e), started_at)

    def _log_sync(
        self,
        source: str,
        status: str,
        proposals_created: int,
        error_message: Optional[str],
        started_at: datetime,
    ) -> None:
        """Log sync operation to database."""
        with get_db_context() as db:
            log = FeedSyncLog(
                source=source,
                status=status,
                proposals_created=proposals_created,
                error_message=error_message,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )
            db.add(log)
            db.commit()
