import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.db.models import User, Scan, UsageLog, Certification
from app.config import get_settings


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def generate_api_key() -> str:
    settings = get_settings()
    return f"{settings.api_key_prefix}{secrets.token_urlsafe(32)}"


def create_user(db: Session, email: str, plan: str = "FREE") -> User:
    raw_api_key = generate_api_key()
    user = User(
        email=email,
        api_key_hash=hash_api_key(raw_api_key),
        plan=plan
    )
    user._raw_api_key = raw_api_key  # Temp attribute for returning to user
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user_by_api_key(db: Session, api_key: str) -> User | None:
    hashed = hash_api_key(api_key)
    return db.query(User).filter(User.api_key_hash == hashed).first()


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.query(User).filter(User.email == email).first()


def create_scan(
    db: Session,
    user_id: str,
    skill_url: str,
    score: int,
    recommendation: str,
    issues: list,
    scan_time_ms: int
) -> Scan:
    scan = Scan(
        user_id=user_id,
        skill_url=skill_url,
        score=score,
        recommendation=recommendation,
        issues_json=issues,
        scan_time_ms=scan_time_ms
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan_by_id(db: Session, scan_id: str) -> Scan | None:
    return db.query(Scan).filter(Scan.id == scan_id).first()


def get_cached_scan(db: Session, skill_url: str, max_age_hours: int = 24) -> Scan | None:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    return db.query(Scan).filter(
        Scan.skill_url == skill_url,
        Scan.created_at > cutoff
    ).order_by(Scan.created_at.desc()).first()


def count_user_scans_this_month(db: Session, user_id: str) -> int:
    now = datetime.now(timezone.utc)
    start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return db.query(Scan).filter(
        Scan.user_id == user_id,
        Scan.created_at >= start_of_month
    ).count()


def log_usage(db: Session, user_id: str, action: str, billed: bool = False, amount_cents: int = 0):
    log = UsageLog(
        user_id=user_id,
        action=action,
        billed=billed,
        amount_cents=amount_cents
    )
    db.add(log)
    db.commit()


def get_usage_count(db: Session, user_id: str, action: str = "SCAN") -> int:
    """Count usage entries for user this month."""
    now = datetime.now(timezone.utc)
    start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return db.query(UsageLog).filter(
        UsageLog.user_id == user_id,
        UsageLog.action == action,
        UsageLog.timestamp >= start_of_month
    ).count()
