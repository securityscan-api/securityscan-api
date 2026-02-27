from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    # Existing
    deepseek_api_key: str
    stripe_secret_key: str = ""
    stripe_publishable_key: str = ""
    stripe_webhook_secret: str = ""
    # Stripe Price IDs (MXN)
    stripe_price_pay_per_scan: str = ""  # e.g. https://buy.stripe.com/xxx
    stripe_price_pro: str = ""           # e.g. https://buy.stripe.com/yyy
    database_url: str = "sqlite:///./securityscan.db"
    api_key_prefix: str = "ss_live_"

    # API Host (for callback URLs)
    api_host: str = "apisecurityscan.net"

    # Admin
    admin_secret: str = ""
    admin_email: str = ""

    # SMTP
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""

    # External APIs (optional)
    nvd_api_key: str = ""
    github_token: str = ""
    anthropic_api_key: str = ""  # Fallback when DeepSeek fails

    # Schedule
    feed_sync_hour: int = 3  # 3am UTC
    digest_day: int = 0  # Monday
    digest_hour: int = 9  # 9am

    model_config = SettingsConfigDict(env_file=".env")


@lru_cache
def get_settings() -> Settings:
    return Settings()
