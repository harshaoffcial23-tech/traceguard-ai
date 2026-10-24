"""
Sensitive data redaction and data exposure inspection.
Guarantees sensitive synthetic PII, credentials, and API keys are redacted from audit logs
and detects verified data exposure in tool results and model outputs.
"""

from __future__ import annotations
import hashlib
import re
from typing import Any, Dict, List, Set, Tuple
from app.models.schemas import DataExposureInspection


# Regex patterns for sensitive synthetic data
PATTERNS = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{4}[ -]?\d{6}[ -]?\d{5}\b"),
    "API_KEY": re.compile(r"\b(?:sk_live|tg_live|AKIA|tg_master)[a-zA-Z0-9_\-]{8,}\b"),
    "DB_PASSWORD": re.compile(r"\bsynth_sec_[a-zA-Z0-9_!@#$%^&*]+\b"),
    "JWT_SECRET": re.compile(r"\bsynth_jwt_[a-zA-Z0-9_!@#$%^&*]+\b"),
}

# Known synthetic sensitive keywords/tokens for exposure checking
KNOWN_PROTECTED_TOKENS = [
    "synth_sec_9948271_x!",
    "tg_live_synth_abcdef1234567890",
    "synth_jwt_signing_key_secret_8372",
    "sk_live_synth_998877665544",
    "AKIA-SYNTH-EXAMPLE-009988",
    "tg_master_synth_token_x991",
    "000-11-2222",
    "000-33-4444",
    "000-55-6666",
    "000-77-8888",
    "000-12-3456",
    "000-23-4567",
    "000-34-5678",
    "000-45-6789",
    "4111-2222-3333-4444",
    "5500-0000-0000-0004",
    "3782-822463-10005",
]


def redact_text(text: str) -> str:
    """Mask sensitive patterns in arbitrary text."""
    if not isinstance(text, str):
        return text

    redacted = text
    redacted = PATTERNS["SSN"].sub("[REDACTED_SSN]", redacted)
    redacted = PATTERNS["CREDIT_CARD"].sub("[REDACTED_CARD]", redacted)
    redacted = PATTERNS["API_KEY"].sub("[REDACTED_KEY]", redacted)
    redacted = PATTERNS["DB_PASSWORD"].sub("[REDACTED_SECRET]", redacted)
    redacted = PATTERNS["JWT_SECRET"].sub("[REDACTED_SECRET]", redacted)

    for token in KNOWN_PROTECTED_TOKENS:
        if token in redacted:
            redacted = redacted.replace(token, "[REDACTED_PROTECTED_DATA]")

    return redacted


def redact_value(val: Any) -> Any:
    """Recursively redact strings inside dictionaries, lists, or primitives."""
    if isinstance(val, str):
        return redact_text(val)
    elif isinstance(val, dict):
        return {k: redact_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [redact_value(item) for item in val]
    elif isinstance(val, tuple):
        return tuple(redact_value(item) for item in val)
    return val


def hash_arguments(args: Dict[str, Any]) -> str:
    """Deterministic hash of raw arguments before redaction for audit traceability."""
    sorted_str = str(sorted(args.items()))
    return hashlib.sha256(sorted_str.encode("utf-8")).hexdigest()[:16]


def inspect_data_exposure(content: Any) -> DataExposureInspection:
    """
    Inspects content (raw or output) to verify whether protected synthetic data
    or sensitive patterns are present.
    """
    if content is None:
        return DataExposureInspection(exposure_detected=False)

    text_to_scan = str(content)
    detected_categories: List[str] = []
    details: List[str] = []

    # Check pattern matches
    if PATTERNS["SSN"].search(text_to_scan):
        detected_categories.append("PII_SSN")
        details.append("Detected SSN pattern in content")

    if PATTERNS["CREDIT_CARD"].search(text_to_scan):
        detected_categories.append("PII_CREDIT_CARD")
        details.append("Detected Credit Card pattern in content")

    if PATTERNS["API_KEY"].search(text_to_scan):
        detected_categories.append("CREDENTIALS_API_KEY")
        details.append("Detected synthetic API key pattern in content")

    if PATTERNS["DB_PASSWORD"].search(text_to_scan) or PATTERNS["JWT_SECRET"].search(text_to_scan):
        detected_categories.append("CREDENTIALS_PASSWORD")
        details.append("Detected synthetic credentials/secret in content")

    # Check known protected tokens
    found_tokens = [tok for tok in KNOWN_PROTECTED_TOKENS if tok in text_to_scan]
    if found_tokens:
        if "SYNTHETIC_VAULT_RECORD" not in detected_categories:
            detected_categories.append("SYNTHETIC_VAULT_RECORD")
        details.append(f"Detected {len(found_tokens)} verified synthetic protected values in content")

    exposure_detected = len(detected_categories) > 0
    redacted_preview = redact_text(text_to_scan)[:300] if exposure_detected else None

    return DataExposureInspection(
        exposure_detected=exposure_detected,
        exposed_categories=detected_categories,
        details=details,
        redacted_preview=redacted_preview,
    )
