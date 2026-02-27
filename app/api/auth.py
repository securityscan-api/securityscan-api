import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.crud import create_user, get_user_by_email
from app.dependencies import get_remaining_scans
from app.payments.stripe import StripeService
from app.config import get_settings

stripe_service = StripeService()
settings = get_settings()

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    # Accepts human emails OR agent identifiers
    # Any non-empty string is valid — no EmailStr restriction
    agent_id: str = ""
    email: str = ""  # Kept for backward compatibility
    plan: str = "FREE"


class RegisterResponse(BaseModel):
    api_key: str
    plan: str
    scans_remaining: int | None


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    # Resolve identifier: agent_id takes priority, then email, then auto-generate
    identifier = request.agent_id or request.email
    if not identifier:
        identifier = f"agent-{uuid.uuid4().hex[:12]}@securityscan.ai"

    # Validate plan
    valid_plans = ["FREE", "PAY_PER_SCAN", "PRO"]
    if request.plan not in valid_plans:
        raise HTTPException(status_code=400, detail=f"Invalid plan. Must be one of: {valid_plans}")

    # Duplicate check: raise 400 if identifier already registered
    existing = get_user_by_email(db, identifier)
    if existing:
        raise HTTPException(status_code=400, detail=f"{identifier} already registered")

    # Create new user
    user = create_user(db, identifier, request.plan)

    # Create Stripe customer if Stripe is configured
    if settings.stripe_secret_key:
        try:
            customer_id = stripe_service.create_customer(identifier)
            if customer_id:
                user.stripe_customer_id = customer_id
                db.commit()
        except Exception:
            pass  # Continue without Stripe if it fails

    return RegisterResponse(
        api_key=user._raw_api_key,
        plan=user.plan,
        scans_remaining=get_remaining_scans(user, db)
    )


@router.post("/register/agent", response_model=RegisterResponse, status_code=201)
def register_agent(db: Session = Depends(get_db)):
    """Zero-friction endpoint for agents: auto-generates identifier, returns key immediately."""
    identifier = f"agent-{uuid.uuid4().hex}@securityscan.ai"
    user = create_user(db, identifier, "FREE")
    return RegisterResponse(
        api_key=user._raw_api_key,
        plan=user.plan,
        scans_remaining=get_remaining_scans(user, db)
    )
