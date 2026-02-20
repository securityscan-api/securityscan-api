"""Admin API endpoints for security feeds management."""

import secrets
import asyncio
from datetime import datetime
from typing import Optional, Literal
from fastapi import APIRouter, Depends, HTTPException, Header, BackgroundTasks, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import RuleProposal, ApprovedRule, FeedSyncLog
from app.config import get_settings
from app.feeds.monitor import FeedMonitor
from app.feeds.digest import DigestSender

# Use obscure prefix - not /admin
router = APIRouter(prefix="/_s", tags=["Internal"])


# ============ Auth Dependency ============

async def verify_admin_key(
    request: Request,
    authorization: str = Header(None, alias="Authorization"),
):
    """Verify admin access with constant-time comparison."""
    settings = get_settings()

    # Add small random delay to prevent timing attacks
    await asyncio.sleep(secrets.randbelow(100) / 1000)

    if not settings.admin_secret:
        raise HTTPException(status_code=404)  # Don't reveal endpoint exists

    # Expect: Authorization: Bearer <token>
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=404)  # Don't reveal endpoint exists

    token = authorization[7:]  # Remove "Bearer "

    # Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(token, settings.admin_secret):
        raise HTTPException(status_code=404)  # Don't reveal endpoint exists

    return True


# ============ Request/Response Models ============

class SyncRequest(BaseModel):
    source: Literal["all", "nvd", "owasp_llm"] = "all"


class SyncResponse(BaseModel):
    status: str
    job_id: Optional[str] = None
    results: Optional[dict] = None


class ProposalDecision(BaseModel):
    id: str
    action: Literal["APPROVE", "REJECT"]
    pattern_override: Optional[str] = None
    reason: Optional[str] = None


class ReviewRequest(BaseModel):
    decisions: list[ProposalDecision]


class ReviewResponse(BaseModel):
    approved: int
    rejected: int


class ProposalResponse(BaseModel):
    id: str
    source: str
    source_id: str
    title: str
    description: str
    severity: str
    suggested_pattern: Optional[str]
    suggested_detector: Optional[str]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class ProposalsListResponse(BaseModel):
    proposals: list[ProposalResponse]
    total: int
    pending_count: int


class DigestResponse(BaseModel):
    sent: bool
    sent_to: Optional[str] = None
    proposals_included: Optional[int] = None
    reason: Optional[str] = None


# ============ Sync Endpoints ============

@router.post("/feeds/sync", response_model=SyncResponse)
async def trigger_feed_sync(
    request: SyncRequest,
    background_tasks: BackgroundTasks,
    _: bool = Depends(verify_admin_key),
):
    """Force manual synchronization of security feeds."""
    monitor = FeedMonitor()
    results = await monitor.run_sync(request.source)
    return SyncResponse(status="completed", results=results)


# ============ Proposal Endpoints ============

@router.get("/proposals", response_model=ProposalsListResponse)
def list_proposals(
    status: Optional[str] = None,
    page: int = 1,
    limit: int = 20,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin_key),
):
    """List rule proposals with optional filtering."""
    query = db.query(RuleProposal)

    if status:
        query = query.filter(RuleProposal.status == status.upper())

    total = query.count()
    pending_count = db.query(RuleProposal).filter(RuleProposal.status == "PENDING").count()

    proposals = (
        query.order_by(RuleProposal.created_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return ProposalsListResponse(
        proposals=[ProposalResponse.model_validate(p) for p in proposals],
        total=total,
        pending_count=pending_count,
    )


@router.post("/proposals/review", response_model=ReviewResponse)
def review_proposals(
    request: ReviewRequest,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin_key),
):
    """Batch approve/reject rule proposals."""
    approved = 0
    rejected = 0

    for decision in request.decisions:
        proposal = db.query(RuleProposal).filter(RuleProposal.id == decision.id).first()
        if not proposal:
            continue

        if decision.action == "APPROVE":
            proposal.status = "APPROVED"
            proposal.reviewed_at = datetime.utcnow()

            # Create ApprovedRule
            pattern = decision.pattern_override or proposal.suggested_pattern or ""
            rule = ApprovedRule(
                proposal_id=proposal.id,
                detector_type=proposal.suggested_detector or "custom",
                pattern=pattern,
                severity=proposal.severity,
                description=proposal.description[:500],
                is_active=True,
            )
            db.add(rule)
            approved += 1

        elif decision.action == "REJECT":
            proposal.status = "REJECTED"
            proposal.reviewed_at = datetime.utcnow()
            rejected += 1

    db.commit()
    return ReviewResponse(approved=approved, rejected=rejected)


# ============ Digest Endpoints ============

@router.post("/digest/send", response_model=DigestResponse)
async def send_digest(
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin_key),
):
    """Manually trigger email digest."""
    sender = DigestSender(db)
    result = await sender.send_digest()
    return DigestResponse(**result)


# ============ Sync Logs ============

@router.get("/feeds/logs")
def get_sync_logs(
    limit: int = 20,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin_key),
):
    """Get recent feed sync logs."""
    logs = (
        db.query(FeedSyncLog)
        .order_by(FeedSyncLog.started_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "logs": [
            {
                "id": log.id,
                "source": log.source,
                "status": log.status,
                "proposals_created": log.proposals_created,
                "error_message": log.error_message,
                "started_at": log.started_at,
                "completed_at": log.completed_at,
            }
            for log in logs
        ]
    }
