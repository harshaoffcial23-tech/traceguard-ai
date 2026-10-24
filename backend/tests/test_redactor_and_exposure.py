"""
Tests for Sensitive Data Redaction and Data Exposure Verification.
"""

from app.gateway.redactor import hash_arguments, inspect_data_exposure, redact_text, redact_value


def test_redact_ssn():
    raw = "Customer Alice has SSN 000-12-3456 in file."
    redacted = redact_text(raw)
    assert "000-12-3456" not in redacted
    assert "[REDACTED_SSN]" in redacted or "[REDACTED_PROTECTED_DATA]" in redacted


def test_redact_api_key():
    raw = "Export key tg_live_synth_abcdef1234567890 to header"
    redacted = redact_text(raw)
    assert "tg_live_synth_abcdef1234567890" not in redacted
    assert "[REDACTED_KEY]" in redacted or "[REDACTED_PROTECTED_DATA]" in redacted


def test_redact_nested_dict():
    data = {
        "user": "Alice",
        "ssn": "000-11-2222",
        "nested": {
            "token": "sk_live_synth_998877665544",
            "safe": "hello",
        },
    }
    redacted = redact_value(data)
    assert "000-11-2222" not in str(redacted)
    assert "sk_live_synth_998877665544" not in str(redacted)
    assert redacted["user"] == "Alice"
    assert redacted["nested"]["safe"] == "hello"


def test_inspect_data_exposure_positive():
    sample = "Exporting customer: 000-11-2222 with credit card 4111-2222-3333-4444"
    exposure = inspect_data_exposure(sample)
    assert exposure.exposure_detected is True
    assert "PII_SSN" in exposure.exposed_categories
    assert "PII_CREDIT_CARD" in exposure.exposed_categories


def test_inspect_data_exposure_negative():
    sample = "Normal product name: NextGen Enterprise Firewall"
    exposure = inspect_data_exposure(sample)
    assert exposure.exposure_detected is False
    assert len(exposure.exposed_categories) == 0


def test_deterministic_hash():
    args1 = {"a": 1, "b": "secret"}
    args2 = {"b": "secret", "a": 1}
    assert hash_arguments(args1) == hash_arguments(args2)
