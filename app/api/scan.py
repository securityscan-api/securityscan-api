from datetime import datetime
from urllib.parse import unquote
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.crud import create_scan, get_cached_scan, get_scan_by_id, log_usage
from app.db.models import User, Certification, Scan
from app.dependencies import get_current_user, check_scan_limit, get_remaining_scans
from app.scanner.engine import SkillScanner

router = APIRouter(tags=["scan"])


class ScanRequest(BaseModel):
    skill_url: HttpUrl


class IssueResponse(BaseModel):
    type: str
    severity: str
    line: int
    description: str
    snippet: str


class ScanResponse(BaseModel):
    scan_id: str
    skill_url: str
    score: int
    recommendation: str
    issues: list
    scan_time_ms: int
    cached: bool
    scans_remaining: int | None = None


@router.post("/scan", response_model=ScanResponse)
async def scan_skill(
    request: ScanRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    skill_url = str(request.skill_url)

    # Check cache first (24h)
    cached = get_cached_scan(db, skill_url)
    if cached:
        return ScanResponse(
            scan_id=cached.id,
            skill_url=cached.skill_url,
            score=cached.score,
            recommendation=cached.recommendation,
            issues=cached.issues_json or [],
            scan_time_ms=cached.scan_time_ms or 0,
            cached=True,
            scans_remaining=get_remaining_scans(user, db)
        )

    # Check scan limit for non-cached scans
    if not check_scan_limit(user, db):
        raise HTTPException(
            status_code=402,
            detail={
                "error": "scan_limit_reached",
                "message": "You've used your free scans. Upgrade to continue.",
                "upgrade_url": "/upgrade"
            }
        )

    # Perform scan (with dynamic rules from database)
    scanner = SkillScanner()
    try:
        result = await scanner.scan(skill_url, db=db)
    finally:
        await scanner.close()

    # Save to database
    scan = create_scan(
        db,
        user_id=user.id,
        skill_url=skill_url,
        score=result.score,
        recommendation=result.recommendation,
        issues=result.issues,
        scan_time_ms=result.scan_time_ms
    )

    # Log usage
    log_usage(db, user.id, "SCAN")

    return ScanResponse(
        scan_id=scan.id,
        skill_url=scan.skill_url,
        score=scan.score,
        recommendation=scan.recommendation,
        issues=scan.issues_json or [],
        scan_time_ms=scan.scan_time_ms or 0,
        cached=False,
        scans_remaining=get_remaining_scans(user, db)
    )


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan = get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Only allow access to own scans
    if scan.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    return ScanResponse(
        scan_id=scan.id,
        skill_url=scan.skill_url,
        score=scan.score,
        recommendation=scan.recommendation,
        issues=scan.issues_json or [],
        scan_time_ms=scan.scan_time_ms or 0,
        cached=True,
        scans_remaining=get_remaining_scans(user, db)
    )


# ============ Public Report Endpoint ============

class PublicReportResponse(BaseModel):
    skill_url: str
    score: int
    recommendation: str
    certified: bool
    certified_at: datetime | None
    cert_hash: str | None
    issues_summary: dict


@router.get("/report/{skill_url:path}")
def get_public_report(
    skill_url: str,
    db: Session = Depends(get_db)
):
    """
    Public endpoint to view scan report for a skill.
    Returns certification status and summary (no auth required).
    """
    # URL decode the skill_url
    decoded_url = unquote(skill_url)

    # Check for certification first
    cert = db.query(Certification).filter(
        Certification.skill_url == decoded_url
    ).first()

    if cert:
        # Certified skill - get the associated scan
        scan = db.query(Scan).filter(Scan.id == cert.scan_id).first()
        issues = scan.issues_json or [] if scan else []

        # Count issues by severity
        issues_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for issue in issues:
            sev = issue.get("severity", "MEDIUM")
            if sev in issues_summary:
                issues_summary[sev] += 1

        return PublicReportResponse(
            skill_url=decoded_url,
            score=cert.score,
            recommendation="SAFE" if cert.score >= 80 else "CAUTION",
            certified=True,
            certified_at=cert.certified_at,
            cert_hash=cert.cert_hash,
            issues_summary=issues_summary
        )

    # Not certified - check for any cached scan
    cached = get_cached_scan(db, decoded_url)
    if cached:
        issues = cached.issues_json or []
        issues_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for issue in issues:
            sev = issue.get("severity", "MEDIUM")
            if sev in issues_summary:
                issues_summary[sev] += 1

        return PublicReportResponse(
            skill_url=decoded_url,
            score=cached.score,
            recommendation=cached.recommendation,
            certified=False,
            certified_at=None,
            cert_hash=None,
            issues_summary=issues_summary
        )

    raise HTTPException(
        status_code=404,
        detail="No report found for this skill. Request a scan first."
    )
