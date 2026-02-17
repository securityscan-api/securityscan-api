from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.crud import count_user_scans_this_month
from app.db.models import User
from app.dependencies import get_current_user, get_remaining_scans, PLAN_LIMITS

router = APIRouter(tags=["usage"])


class UsageResponse(BaseModel):
    email: str
    plan: str
    scans_used: int
    scans_remaining: int | None
    scans_limit: int | None


@router.get("/usage", response_model=UsageResponse)
def get_usage(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    used = count_user_scans_this_month(db, user.id)
    remaining = get_remaining_scans(user, db)
    limit = PLAN_LIMITS.get(user.plan)

    return UsageResponse(
        email=user.email,
        plan=user.plan,
        scans_used=used,
        scans_remaining=remaining,
        scans_limit=limit
    )
