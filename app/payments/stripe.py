import stripe
from app.config import get_settings

settings = get_settings()
stripe.api_key = settings.stripe_secret_key


class StripeService:
  def create_customer(self, email: str) -> str:
      if not settings.stripe_secret_key:
          return ""
      customer = stripe.Customer.create(email=email)
      return customer.id

  def create_checkout_session(self, customer_id: str, plan: str,
      success_url: str = "https://apisecurityscan.net/billing/success",
      cancel_url: str = "https://apisecurityscan.net/billing/cancelled") -> str:
      if not settings.stripe_secret_key:
          return ""
      price_map = {
          "PRO": {"price_id": settings.stripe_price_pro, "mode": "subscription"},
          "PAY_PER_SCAN": {"price_id": settings.stripe_price_pay_per_scan, "mode": "payment"},
      }
      config = price_map.get(plan)
      if not config or not config["price_id"]:
          raise ValueError(f"Unknown or unconfigured plan: {plan}")
      session = stripe.checkout.Session.create(
          customer=customer_id,
          payment_method_types=["card"],
          line_items=[{"price": config["price_id"], "quantity": 1}],
          mode=config["mode"],
          success_url=success_url + "?session_id={CHECKOUT_SESSION_ID}",
          cancel_url=cancel_url,
          metadata={"plan": plan}
      )
      return session.url

  def handle_webhook_event(self, payload: bytes, sig_header: str) -> dict:
      endpoint_secret = settings.stripe_webhook_secret
      if not endpoint_secret:
          raise ValueError("Stripe webhook secret not configured")
      return stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
