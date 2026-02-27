from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.crud import get_user_by_api_key
from app.db.models import User


PLAN_LIMITS = {
    "FREE": 5,
    "PAY_PER_SCAN": None,  # Unlimited (pay per use)
    "PRO": None,  # Unlimited
}


async def get_current_user(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db)
) -> User:
    """Validate API key and return user."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    user = get_user_by_api_key(db, x_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return user


def check_scan_limit(user: User, db: Session) -> bool:
    """Check if user has remaining scans."""
    from app.db.crud import count_user_scans_this_month

    limit = PLAN_LIMITS.get(user.plan)
    if limit is None:
        return True

    used = count_user_scans_this_month(db, user.id)
    return used < limit


def get_remaining_scans(user: User, db: Session) -> int | None:
    """Get remaining scans for user, or None if unlimited."""
    from app.db.crud import count_user_scans_this_month

    limit = PLAN_LIMITS.get(user.plan)
    if limit is None:
        return None

    used = count_user_scans_this_month(db, user.id)
    return max(0, limit - used)
