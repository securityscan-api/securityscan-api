"""APScheduler configuration for security feeds monitoring."""

import logging
from contextlib import asynccontextmanager

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from app.config import get_settings
from app.db.database import SessionLocal
from app.feeds.monitor import FeedMonitor
from app.feeds.digest import DigestSender

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def run_feed_sync():
    """Scheduled job: Run daily feed sync at 3am UTC."""
    logger.info("Starting scheduled feed sync")
    try:
        monitor = FeedMonitor()
        results = await monitor.sync_all()
        total_proposals = results.get("total_proposals", 0)
        logger.info(f"Scheduled feed sync completed: {total_proposals} new proposals")
    except Exception as e:
        logger.error(f"Scheduled feed sync failed: {e}")


async def run_weekly_digest():
    """Scheduled job: Send weekly digest on Monday 9am."""
    logger.info("Starting scheduled weekly digest")
    db = SessionLocal()
    try:
        sender = DigestSender(db)
        result = await sender.send_digest()
        if result.get("sent"):
            logger.info(f"Weekly digest sent: {result}")
        else:
            logger.info(f"Weekly digest skipped: {result.get('reason')}")
    except Exception as e:
        logger.error(f"Scheduled digest failed: {e}")
    finally:
        db.close()


def setup_scheduler():
    """Configure and start the scheduler with feed sync and digest jobs."""
    settings = get_settings()

    # Daily feed sync at configured hour (default 3am UTC)
    scheduler.add_job(
        run_feed_sync,
        CronTrigger(hour=settings.feed_sync_hour, minute=0),
        id="feed_sync",
        name="Daily Security Feed Sync",
        replace_existing=True,
    )

    # Weekly digest at configured day/hour (default Monday 9am)
    scheduler.add_job(
        run_weekly_digest,
        CronTrigger(
            day_of_week=settings.digest_day,
            hour=settings.digest_hour,
            minute=0,
        ),
        id="weekly_digest",
        name="Weekly Security Digest",
        replace_existing=True,
    )

    scheduler.start()
    logger.info(
        f"Scheduler started: feed sync at {settings.feed_sync_hour}:00 UTC daily, "
        f"digest on day {settings.digest_day} at {settings.digest_hour}:00"
    )


def shutdown_scheduler():
    """Shutdown the scheduler gracefully."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler shutdown")


@asynccontextmanager
async def lifespan(app):
    """FastAPI lifespan context manager for scheduler and MCP."""
    setup_scheduler()

    # Start MCP session manager if available
    mcp_session_manager = None
    try:
        from app.mcp_server import get_mcp_session_manager
        mcp_session_manager = get_mcp_session_manager()
        async with mcp_session_manager.run():
            logger.info("MCP session manager started")
            yield
    except ImportError:
        logger.warning("MCP server not available")
        yield
    except Exception as e:
        logger.warning(f"MCP session manager failed to start: {e}")
        yield

    shutdown_scheduler()
