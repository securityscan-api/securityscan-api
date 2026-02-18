import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from app.feeds.monitor import FeedsMonitor


@pytest.mark.asyncio
async def test_monitor_runs_all_fetchers():
    """FeedsMonitor runs NVD and OWASP fetchers."""
    with patch("app.feeds.monitor.get_settings") as mock_settings:
        mock_settings.return_value.nvd_api_key = ""
        mock_settings.return_value.github_token = ""

        monitor = FeedsMonitor()

        with patch.object(monitor.nvd_fetcher, "fetch", new_callable=AsyncMock) as nvd_mock, \
             patch.object(monitor.owasp_fetcher, "fetch", new_callable=AsyncMock) as owasp_mock, \
             patch.object(monitor.proposal_generator, "create_proposals_batch") as gen_mock, \
             patch.object(monitor, "_log_sync"):

            nvd_mock.return_value = [{"source_id": "CVE-1"}]
            owasp_mock.return_value = [{"source_id": "OWASP-1"}]
            gen_mock.return_value = 1

            result = await monitor.run_sync()

        assert nvd_mock.called
        assert owasp_mock.called
        assert result["total_proposals"] == 2


@pytest.mark.asyncio
async def test_monitor_handles_fetcher_failure():
    """FeedsMonitor continues if one fetcher fails."""
    with patch("app.feeds.monitor.get_settings") as mock_settings:
        mock_settings.return_value.nvd_api_key = ""
        mock_settings.return_value.github_token = ""

        monitor = FeedsMonitor()

        with patch.object(monitor.nvd_fetcher, "fetch", new_callable=AsyncMock) as nvd_mock, \
             patch.object(monitor.owasp_fetcher, "fetch", new_callable=AsyncMock) as owasp_mock, \
             patch.object(monitor.proposal_generator, "create_proposals_batch") as gen_mock, \
             patch.object(monitor, "_log_sync"):

            nvd_mock.side_effect = Exception("NVD API down")
            owasp_mock.return_value = [{"source_id": "OWASP-1"}]
            gen_mock.return_value = 1

            result = await monitor.run_sync()

        assert "NVD" in result["errors"]
        assert result["total_proposals"] == 1
