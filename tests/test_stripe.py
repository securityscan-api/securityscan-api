import pytest
from unittest.mock import patch, MagicMock
from app.payments.stripe import StripeService


def test_stripe_service_init():
    service = StripeService()
    assert service is not None


@patch('stripe.Customer.create')
def test_create_customer(mock_create):
    mock_create.return_value = MagicMock(id="cus_test123")

    service = StripeService()
    customer_id = service.create_customer("test@example.com")

    assert customer_id == "cus_test123"
    mock_create.assert_called_once_with(email="test@example.com")


@patch('stripe.checkout.Session.create')
def test_create_checkout_session_pro(mock_create):
    mock_create.return_value = MagicMock(url="https://checkout.stripe.com/test")

    service = StripeService()
    url = service.create_checkout_session("cus_123", "PRO")

    assert url == "https://checkout.stripe.com/test"
    mock_create.assert_called_once()
    call_args = mock_create.call_args
    assert call_args.kwargs["mode"] == "subscription"


@patch('stripe.checkout.Session.create')
def test_create_checkout_session_pay_per_scan(mock_create):
    mock_create.return_value = MagicMock(url="https://checkout.stripe.com/test2")

    service = StripeService()
    url = service.create_checkout_session("cus_123", "PAY_PER_SCAN")

    assert url == "https://checkout.stripe.com/test2"
    call_args = mock_create.call_args
    assert call_args.kwargs["mode"] == "payment"


def test_create_checkout_invalid_plan():
    service = StripeService()
    with pytest.raises(ValueError, match="Unknown plan"):
        service.create_checkout_session("cus_123", "INVALID")
