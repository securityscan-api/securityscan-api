import pytest
from app.db.models import RuleProposal, ApprovedRule, FeedSyncLog


def test_rule_proposal_has_required_fields():
    """RuleProposal model has all required columns."""
    columns = [c.name for c in RuleProposal.__table__.columns]
    required = ["id", "source", "source_id", "title", "description",
                "severity", "suggested_pattern", "suggested_detector",
                "status", "reviewed_at", "created_at"]
    for col in required:
        assert col in columns, f"Missing column: {col}"


def test_approved_rule_has_required_fields():
    """ApprovedRule model has all required columns."""
    columns = [c.name for c in ApprovedRule.__table__.columns]
    required = ["id", "proposal_id", "detector_type", "pattern",
                "severity", "description", "is_active", "created_at"]
    for col in required:
        assert col in columns, f"Missing column: {col}"


def test_feed_sync_log_has_required_fields():
    """FeedSyncLog model has all required columns."""
    columns = [c.name for c in FeedSyncLog.__table__.columns]
    required = ["id", "source", "status", "proposals_created",
                "error_message", "started_at", "completed_at"]
    for col in required:
        assert col in columns, f"Missing column: {col}"
