"""Email digest for pending rule proposals."""

import logging
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import aiosmtplib
from sqlalchemy.orm import Session

from app.db.models import RuleProposal
from app.config import get_settings

logger = logging.getLogger(__name__)


class DigestSender:
    """Sends weekly email digest of pending rule proposals."""

    def __init__(self, db: Session):
        self.db = db
        self.settings = get_settings()

    def get_pending_proposals(self) -> list[RuleProposal]:
        """Get all pending proposals."""
        return (
            self.db.query(RuleProposal)
            .filter(RuleProposal.status == "PENDING")
            .order_by(RuleProposal.severity, RuleProposal.created_at.desc())
            .all()
        )

    def build_digest_html(self, proposals: list[RuleProposal]) -> str:
        """Build HTML content for the digest email."""
        # Group by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for p in proposals:
            if p.severity in by_severity:
                by_severity[p.severity].append(p)

        html = """
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .header { background: #2563eb; color: white; padding: 20px; }
        .content { padding: 20px; }
        .severity { margin: 20px 0; }
        .severity-title { padding: 10px; color: white; font-weight: bold; }
        .critical { background: #dc2626; }
        .high { background: #ea580c; }
        .medium { background: #ca8a04; }
        .low { background: #65a30d; }
        .proposal { border: 1px solid #ddd; padding: 15px; margin: 10px 0; }
        .proposal-title { font-weight: bold; margin-bottom: 5px; }
        .proposal-source { color: #666; font-size: 0.9em; }
        .proposal-desc { margin-top: 10px; }
        .footer { background: #f3f4f6; padding: 20px; text-align: center; color: #666; }
        .cta { display: inline-block; background: #2563eb; color: white; padding: 12px 24px;
               text-decoration: none; border-radius: 5px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SecurityScan API Digest</h1>
        <p>Weekly summary of pending rule proposals</p>
    </div>
    <div class="content">
        <p>You have <strong>%d pending proposals</strong> awaiting review.</p>
""" % len(proposals)

        for severity, items in by_severity.items():
            if not items:
                continue
            css_class = severity.lower()
            html += f"""
        <div class="severity">
            <div class="severity-title {css_class}">{severity} ({len(items)})</div>
"""
            for p in items:
                html += f"""
            <div class="proposal">
                <div class="proposal-title">{self._escape_html(p.title)}</div>
                <div class="proposal-source">{p.source} | {p.source_id}</div>
                <div class="proposal-desc">{self._escape_html(p.description[:200])}...</div>
            </div>
"""
            html += "        </div>\n"

        html += """
        <a href="#" class="cta">Review Proposals</a>
    </div>
    <div class="footer">
        <p>SecurityScan API</p>
        <p>Generated on %s UTC</p>
    </div>
</body>
</html>
""" % datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

        return html

    def build_digest_text(self, proposals: list[RuleProposal]) -> str:
        """Build plain text content for the digest email."""
        lines = [
            "SecurityScan API Digest",
            "=" * 40,
            f"\nYou have {len(proposals)} pending proposals awaiting review.\n",
        ]

        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for p in proposals:
            if p.severity in by_severity:
                by_severity[p.severity].append(p)

        for severity, items in by_severity.items():
            if not items:
                continue
            lines.append(f"\n{severity} ({len(items)})")
            lines.append("-" * 30)
            for p in items:
                lines.append(f"\n* {p.title}")
                lines.append(f"  Source: {p.source} | {p.source_id}")
                lines.append(f"  {p.description[:100]}...")

        lines.append(f"\n\nGenerated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC")
        return "\n".join(lines)

    async def send_digest(self) -> dict:
        """Send the weekly digest email if there are pending proposals."""
        proposals = self.get_pending_proposals()

        if not proposals:
            logger.info("No pending proposals, skipping digest")
            return {"sent": False, "reason": "no_pending_proposals"}

        if not self.settings.admin_email:
            logger.warning("No admin email configured, cannot send digest")
            return {"sent": False, "reason": "no_admin_email"}

        if not self.settings.smtp_user or not self.settings.smtp_password:
            logger.warning("SMTP credentials not configured, cannot send digest")
            return {"sent": False, "reason": "smtp_not_configured"}

        # Build email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"SecurityScan API: {len(proposals)} Pending Rule Proposals"
        msg["From"] = self.settings.smtp_user
        msg["To"] = self.settings.admin_email

        text_content = self.build_digest_text(proposals)
        html_content = self.build_digest_html(proposals)

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        # Send email
        try:
            await aiosmtplib.send(
                msg,
                hostname=self.settings.smtp_host,
                port=self.settings.smtp_port,
                username=self.settings.smtp_user,
                password=self.settings.smtp_password,
                start_tls=True,
            )
            logger.info(f"Digest sent to {self.settings.admin_email} with {len(proposals)} proposals")
            return {
                "sent": True,
                "sent_to": self.settings.admin_email,
                "proposals_included": len(proposals),
            }
        except Exception as e:
            logger.error(f"Failed to send digest: {e}")
            return {"sent": False, "reason": "smtp_error", "error": str(e)}

    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
