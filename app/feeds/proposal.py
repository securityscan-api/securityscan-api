from typing import Dict, Any
from datetime import datetime, timezone
from app.db.database import get_db_context
from app.db.models import RuleProposal


class ProposalGenerator:
    """Creates RuleProposal records from fetcher data."""

    def create_proposal(self, source: str, data: Dict[str, Any]) -> bool:
        """Create a new RuleProposal if it doesn't exist.

        Returns True if created, False if duplicate.
        """
        with get_db_context() as db:
            # Check for duplicate
            existing = db.query(RuleProposal).filter(
                RuleProposal.source_id == data["source_id"]
            ).first()

            if existing:
                return False

            proposal = RuleProposal(
                source=source,
                source_id=data["source_id"],
                title=data["title"],
                description=data["description"],
                severity=data["severity"],
                suggested_pattern=data.get("suggested_pattern"),
                suggested_detector=data.get("suggested_detector"),
                status="PENDING",
                created_at=datetime.now(timezone.utc),
            )
            db.add(proposal)
            db.commit()
            return True

    def create_proposals_batch(self, source: str, data_list: list) -> int:
        """Create multiple proposals, return count of created."""
        created_count = 0
        for data in data_list:
            if self.create_proposal(source, data):
                created_count += 1
        return created_count
