"""Billing endpoints for Stripe integration."""

import stripe
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import User
from app.dependencies import get_current_user
from app.payments.stripe import StripeService
from app.config import get_settings

router = APIRouter(prefix="/billing", tags=["billing"])
stripe_service = StripeService()
settings = get_settings()


class UpgradeRequest(BaseModel):
    plan: str = "PRO"  # PRO or PAY_PER_SCAN


class UpgradeResponse(BaseModel):
    checkout_url: str
    plan: str


class BillingPortalResponse(BaseModel):
    portal_url: str


class BillingStatusResponse(BaseModel):
    plan: str
    stripe_customer_id: str | None
    scans_used: int
    scans_remaining: int | None


@router.post("/upgrade", response_model=UpgradeResponse)
def create_upgrade_session(
    request: UpgradeRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a Stripe checkout session to upgrade plan.

    Returns a checkout URL where the user/agent can complete payment.
    For AI agents: redirect to this URL or provide to user.

    Plans:
    - PRO: $20/month, unlimited scans
    - PAY_PER_SCAN: $0.10 per scan (prepaid credits)
    """
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=503,
            detail="Payment system not configured"
        )

    valid_plans = ["PRO", "PAY_PER_SCAN"]
    if request.plan not in valid_plans:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan. Must be one of: {valid_plans}"
        )

    # Create Stripe customer if not exists
    if not user.stripe_customer_id:
        customer_id = stripe_service.create_customer(user.email)
        user.stripe_customer_id = customer_id
        db.commit()

    # Generate callback URLs (API returns JSON, no landing page needed)
    base_url = f"https://{settings.api_host}" if hasattr(settings, 'api_host') else "https://194.60.87.137"
    success_url = f"{base_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{base_url}/billing/cancelled"

    try:
        checkout_url = stripe_service.create_checkout_session(
            customer_id=user.stripe_customer_id,
            plan=request.plan,
            success_url=success_url,
            cancel_url=cancel_url
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create checkout: {e}")

    return UpgradeResponse(checkout_url=checkout_url, plan=request.plan)


@router.get("/portal", response_model=BillingPortalResponse)
def get_billing_portal(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get Stripe billing portal URL for subscription management.

    The portal allows:
    - Viewing invoices and payment history
    - Updating payment method
    - Canceling subscription
    """
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=503,
            detail="Payment system not configured"
        )

    if not user.stripe_customer_id:
        raise HTTPException(
            status_code=400,
            detail="No billing account. Use /billing/upgrade first."
        )

    try:
        base_url = f"https://{settings.api_host}" if hasattr(settings, 'api_host') else "https://194.60.87.137"
        session = stripe.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=f"{base_url}/billing/status"
        )
        return BillingPortalResponse(portal_url=session.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create portal: {e}")


@router.get("/status", response_model=BillingStatusResponse)
def get_billing_status(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get current billing status and usage.

    Returns:
    - Current plan (FREE, PRO, PAY_PER_SCAN)
    - Scans used this period
    - Scans remaining (null for unlimited PRO)
    """
    from app.dependencies import get_remaining_scans
    from app.db.crud import get_usage_count

    scans_used = get_usage_count(db, user.id, "SCAN")
    scans_remaining = get_remaining_scans(user, db)

    return BillingStatusResponse(
        plan=user.plan,
        stripe_customer_id=user.stripe_customer_id,
        scans_used=scans_used,
        scans_remaining=scans_remaining
    )


@router.get("/success")
def payment_success(session_id: str = None):
    """
    Payment success callback.

    For API clients: Returns JSON confirmation.
    The webhook will handle the actual plan upgrade.
    """
    return {
        "status": "success",
        "message": "Payment received. Your plan will be upgraded shortly.",
        "session_id": session_id
    }


@router.get("/cancelled")
def payment_cancelled():
    """Payment cancelled callback."""
    return {
        "status": "cancelled",
        "message": "Payment was cancelled. No charges were made."
    }


# ============ Pricing Info (public endpoint) ============

@router.get("/plans")
def get_available_plans():
    """
    Get available pricing plans.

    This is a public endpoint - no authentication required.
    """
    return {
        "plans": [
            {
                "id": "FREE",
                "name": "Free Tier",
                "price": 0,
                "currency": "USD",
                "period": None,
                "features": [
                    "5 scans per month",
                    "Basic vulnerability detection",
                    "24-hour cache"
                ],
                "limits": {
                    "scans_per_month": 5
                }
            },
            {
                "id": "PRO",
                "name": "Pro",
                "price": 20.00,
                "currency": "USD",
                "period": "month",
                "features": [
                    "Unlimited scans",
                    "AI-powered deep analysis",
                    "Priority processing",
                    "Certification badges",
                    "API rate limit: 100/min"
                ],
                "limits": {
                    "scans_per_month": None  # unlimited
                }
            },
            {
                "id": "PAY_PER_SCAN",
                "name": "Pay Per Scan",
                "price": 0.10,
                "currency": "USD",
                "period": "per scan",
                "features": [
                    "Pay only for what you use",
                    "Same features as Pro",
                    "No monthly commitment"
                ],
                "limits": {
                    "minimum_purchase": 10  # $1 minimum
                }
            }
        ],
        "currency": "USD"
    }
