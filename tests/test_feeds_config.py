import pytest
from app.config import Settings


def test_settings_has_admin_fields():
    """Settings includes admin configuration."""
    fields = Settings.model_fields.keys()
    assert "admin_secret" in fields
    assert "admin_email" in fields


def test_settings_has_smtp_fields():
    """Settings includes SMTP configuration."""
    fields = Settings.model_fields.keys()
    assert "smtp_host" in fields
    assert "smtp_port" in fields


def test_settings_has_schedule_fields():
    """Settings includes schedule configuration."""
    fields = Settings.model_fields.keys()
    assert "feed_sync_hour" in fields
    assert "digest_day" in fields
