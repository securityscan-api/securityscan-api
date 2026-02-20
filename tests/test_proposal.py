import pytest
from unittest.mock import MagicMock, patch
from app.feeds.proposal import ProposalGenerator


def test_proposal_generator_creates_proposals():
    """ProposalGenerator creates RuleProposal from fetcher data."""
    generator = ProposalGenerator()

    fetcher_data = {
        "source_id": "CVE-2024-1234",
        "title": "Test CVE",
        "description": "A test vulnerability",
        "severity": "CRITICAL",
        "suggested_pattern": None,
        "suggested_detector": "cve_check",
    }

    with patch("app.feeds.proposal.get_db_context") as mock_db:
        mock_session = MagicMock()
        mock_db.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_db.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter.return_value.first.return_value = None

        created = generator.create_proposal("NVD", fetcher_data)

    assert created is True


def test_proposal_generator_skips_duplicates():
    """ProposalGenerator skips existing proposals."""
    generator = ProposalGenerator()

    fetcher_data = {
        "source_id": "CVE-2024-1234",
        "title": "Test CVE",
        "description": "A test vulnerability",
        "severity": "CRITICAL",
        "suggested_pattern": None,
        "suggested_detector": "cve_check",
    }

    with patch("app.feeds.proposal.get_db_context") as mock_db:
        mock_session = MagicMock()
        mock_db.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_db.return_value.__exit__ = MagicMock(return_value=False)
        # Simulate existing proposal
        mock_session.query.return_value.filter.return_value.first.return_value = MagicMock()

        created = generator.create_proposal("NVD", fetcher_data)

    assert created is False
