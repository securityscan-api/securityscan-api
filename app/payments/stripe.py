import stripe
from app.config import get_settings

settings = get_settings()
stripe.api_key = settings.stripe_secret_key


class StripeService:
    def create_customer(self, email: str) -> str:
        """Create Stripe customer and return ID."""
        if not settings.stripe_secret_key:
            return ""  # Skip if no Stripe key configured
        customer = stripe.Customer.create(email=email)
        return customer.id

    def create_checkout_session(
        self,
        customer_id: str,
        plan: str,
        success_url: str = "https://securityscan.ai/success",
        cancel_url: str = "https://securityscan.ai/cancel"
    ) -> str:
        """Create checkout session and return URL."""
        if not settings.stripe_secret_key:
            return ""

        # Price configurations - these would be created in Stripe dashboard
        price_configs = {
            "PRO": {"amount": 2000, "currency": "usd", "recurring": {"interval": "month"}},
            "PAY_PER_SCAN": {"amount": 10, "currency": "usd"},  # $0.10
        }

        config = price_configs.get(plan)
        if not config:
            raise ValueError(f"Unknown plan: {plan}")

        mode = "subscription" if plan == "PRO" else "payment"

        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": config["currency"],
                    "unit_amount": config["amount"],
                    "product_data": {"name": f"SecurityScan {plan}"},
                    **({"recurring": config["recurring"]} if "recurring" in config else {})
                },
                "quantity": 1
            }],
            mode=mode,
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={"plan": plan}
        )
        return session.url

    def handle_webhook_event(self, payload: bytes, sig_header: str) -> dict:
        """Verify and parse Stripe webhook."""
        endpoint_secret = settings.stripe_webhook_secret
        if not endpoint_secret:
            raise ValueError("Stripe webhook secret not configured")
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
        return event
