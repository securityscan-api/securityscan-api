from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.crud import create_user, get_user_by_email
from app.dependencies import get_remaining_scans

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    plan: str = "FREE"


class RegisterResponse(BaseModel):
    api_key: str
    plan: str
    scans_remaining: int | None


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    # Check if email already exists
    existing = get_user_by_email(db, request.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Validate plan
    valid_plans = ["FREE", "PAY_PER_SCAN", "PRO"]
    if request.plan not in valid_plans:
        raise HTTPException(status_code=400, detail=f"Invalid plan. Must be one of: {valid_plans}")

    # Create user
    user = create_user(db, request.email, request.plan)
    remaining = get_remaining_scans(user, db)

    return RegisterResponse(
        api_key=user._raw_api_key,
        plan=user.plan,
        scans_remaining=remaining
    )
