"""
SecurityScan MCP Server - Exposes security scanning tools for AI agents.

This module provides MCP (Model Context Protocol) tools that allow AI agents
to scan skills, repositories, and configurations for security vulnerabilities.
"""

from typing import Optional
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP

from app.db.database import get_db
from app.db.models import Certification, Scan
from app.db.crud import get_cached_scan, create_scan, create_user, get_user_by_email
from app.scanner.engine import SkillScanner


# Create the MCP server instance
mcp = FastMCP(
    name="SecurityScan",
    instructions="""
    SecurityScan API - AI-powered security scanner for skills and repositories.

    Use these tools to:
    - scan_skill: Analyze a GitHub repository or skill URL for security vulnerabilities
    - get_report: Retrieve a public security report for a previously scanned skill
    - check_certification: Verify if a skill has been certified as safe

    All scans use pattern matching and AI analysis to detect:
    - Hardcoded credentials and secrets
    - Remote code execution vulnerabilities
    - Data exfiltration attempts
    - Privilege escalation risks
    - Prompt injection vulnerabilities
    """,
    json_response=True,
    streamable_http_path="/",  # Mount at / so full path is /mcp when mounted at /mcp
)


# Response models for structured output
class ScanResult(BaseModel):
    """Security scan result"""
    scan_id: str = Field(description="Unique identifier for this scan")
    skill_url: str = Field(description="URL that was scanned")
    score: int = Field(description="Security score from 0-100 (higher is safer)")
    recommendation: str = Field(description="SAFE, CAUTION, or DANGEROUS")
    issues_count: int = Field(description="Number of security issues found")
    issues: list = Field(description="List of detected security issues")
    cached: bool = Field(description="Whether this result was from cache")


class ReportResult(BaseModel):
    """Public security report"""
    skill_url: str
    score: int
    recommendation: str
    certified: bool
    certified_at: Optional[str] = None
    cert_hash: Optional[str] = None
    issues_summary: dict = Field(description="Count of issues by severity")


class CertificationResult(BaseModel):
    """Certification check result"""
    skill_url: str
    is_certified: bool
    score: Optional[int] = None
    certified_at: Optional[str] = None
    cert_hash: Optional[str] = None


# ============ MCP Tools ============

@mcp.tool()
async def scan_skill(skill_url: str) -> ScanResult:
    """
    Scan a GitHub repository or skill URL for security vulnerabilities.

    This tool performs static analysis and AI-powered detection to identify:
    - Hardcoded credentials and API keys
    - Remote code execution patterns
    - Data exfiltration attempts
    - Privilege escalation risks
    - OWASP LLM Top 10 vulnerabilities

    Args:
        skill_url: GitHub repository URL (e.g., https://github.com/owner/repo)
                   or raw file URL to scan

    Returns:
        ScanResult with security score (0-100), recommendation, and detected issues.
        Score >= 80 is SAFE, 50-79 is CAUTION, < 50 is DANGEROUS.

    Example:
        scan_skill("https://github.com/anthropics/anthropic-sdk-python")
    """
    with get_db() as db:
        # Check cache first
        cached = get_cached_scan(db, skill_url)
        if cached:
            return ScanResult(
                scan_id=cached.id,
                skill_url=cached.skill_url,
                score=cached.score,
                recommendation=cached.recommendation,
                issues_count=len(cached.issues_json or []),
                issues=cached.issues_json or [],
                cached=True
            )

        # Get or create MCP system user
        mcp_user = get_user_by_email(db, "mcp@system.internal")
        if not mcp_user:
            mcp_user = create_user(db, "mcp@system.internal")

        # Perform scan
        scanner = SkillScanner()
        try:
            result = await scanner.scan(skill_url, db=db)
        finally:
            await scanner.close()

        # Save to database
        scan = create_scan(
            db,
            user_id=mcp_user.id,
            skill_url=skill_url,
            score=result.score,
            recommendation=result.recommendation,
            issues=result.issues,
            scan_time_ms=result.scan_time_ms
        )

        return ScanResult(
            scan_id=scan.id,
            skill_url=scan.skill_url,
            score=scan.score,
            recommendation=scan.recommendation,
            issues_count=len(scan.issues_json or []),
            issues=scan.issues_json or [],
            cached=False
        )


@mcp.tool()
def get_report(skill_url: str) -> ReportResult:
    """
    Get the public security report for a skill.

    Returns the most recent scan results and certification status.
    This is useful to check if a skill has been previously scanned
    without triggering a new scan.

    Args:
        skill_url: The skill URL to get the report for

    Returns:
        ReportResult with score, certification status, and issues summary.
        Returns error if no report exists for this URL.

    Example:
        get_report("https://github.com/jlowin/fastmcp")
    """
    with get_db() as db:
        # Check for certification
        cert = db.query(Certification).filter(
            Certification.skill_url == skill_url
        ).first()

        if cert:
            scan = db.query(Scan).filter(Scan.id == cert.scan_id).first()
            issues = scan.issues_json or [] if scan else []

            issues_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for issue in issues:
                sev = issue.get("severity", "MEDIUM")
                if sev in issues_summary:
                    issues_summary[sev] += 1

            return ReportResult(
                skill_url=skill_url,
                score=cert.score,
                recommendation="SAFE" if cert.score >= 80 else "CAUTION",
                certified=True,
                certified_at=cert.certified_at.isoformat() if cert.certified_at else None,
                cert_hash=cert.cert_hash,
                issues_summary=issues_summary
            )

        # Check for cached scan
        cached = get_cached_scan(db, skill_url)
        if cached:
            issues = cached.issues_json or []
            issues_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for issue in issues:
                sev = issue.get("severity", "MEDIUM")
                if sev in issues_summary:
                    issues_summary[sev] += 1

            return ReportResult(
                skill_url=skill_url,
                score=cached.score,
                recommendation=cached.recommendation,
                certified=False,
                certified_at=None,
                cert_hash=None,
                issues_summary=issues_summary
            )

        raise ValueError(f"No report found for {skill_url}. Use scan_skill() first.")


@mcp.tool()
def check_certification(skill_url: str) -> CertificationResult:
    """
    Check if a skill has been certified as safe.

    Certification indicates the skill has been scanned, reviewed,
    and approved by a human administrator. Certified skills have
    a cryptographic hash that can be verified.

    Args:
        skill_url: The skill URL to check certification for

    Returns:
        CertificationResult indicating if the skill is certified,
        along with certification details if available.

    Example:
        check_certification("https://github.com/anthropics/anthropic-cookbook")
    """
    with get_db() as db:
        cert = db.query(Certification).filter(
            Certification.skill_url == skill_url
        ).first()

        if cert:
            return CertificationResult(
                skill_url=skill_url,
                is_certified=True,
                score=cert.score,
                certified_at=cert.certified_at.isoformat() if cert.certified_at else None,
                cert_hash=cert.cert_hash
            )

        return CertificationResult(
            skill_url=skill_url,
            is_certified=False,
            score=None,
            certified_at=None,
            cert_hash=None
        )


# ============ MCP Resources ============

@mcp.resource("stats://overview")
def get_stats() -> str:
    """Get overview statistics of the SecurityScan service."""
    with get_db() as db:
        total_scans = db.query(Scan).count()
        total_certs = db.query(Certification).count()

        return f"""SecurityScan API Statistics:
- Total scans performed: {total_scans}
- Certified skills: {total_certs}
- Service status: operational
"""


# Export for integration with FastAPI
def get_mcp_app():
    """Get the MCP ASGI app for mounting."""
    return mcp.streamable_http_app()


def get_mcp_session_manager():
    """Get the MCP session manager for lifespan."""
    return mcp.session_manager
