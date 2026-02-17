from fastapi import APIRouter, Request, HTTPException
from sqlalchemy.orm import Session
from app.db.database import SessionLocal
from app.db.models import User
from app.payments.stripe import StripeService
from app.config import get_settings

router = APIRouter(tags=["webhooks"])
stripe_service = StripeService()
settings = get_settings()


@router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not sig_header:
        raise HTTPException(status_code=400, detail="Missing stripe-signature header")

    # If no webhook secret configured, just acknowledge
    if not settings.stripe_webhook_secret:
        return {"status": "webhook_secret_not_configured"}

    try:
        event = stripe_service.handle_webhook_event(payload, sig_header)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid payload: {e}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook error: {e}")

    db = SessionLocal()
    try:
        if event["type"] == "checkout.session.completed":
            session = event["data"]["object"]
            customer_id = session.get("customer")
            plan = session.get("metadata", {}).get("plan", "PRO")

            # Update user plan
            if customer_id:
                user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
                if user:
                    user.plan = plan
                    db.commit()

        elif event["type"] == "customer.subscription.deleted":
            subscription = event["data"]["object"]
            customer_id = subscription.get("customer")

            # Downgrade user to FREE
            if customer_id:
                user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
                if user:
                    user.plan = "FREE"
                    db.commit()

        elif event["type"] == "invoice.payment_failed":
            # Log the failure but don't immediately downgrade
            pass

    finally:
        db.close()

    return {"status": "success", "event_type": event["type"]}
