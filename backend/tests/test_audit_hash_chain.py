"""
Tests for Stage 6: Tamper-Evident Hash-Linked Audit Chain.
Verifies:
1. Every newly persisted audit event is cryptographically linked to its predecessor.
2. The audit chain verification endpoint returns is_valid=True for an unmodified ledger.
3. Out-of-band record tampering in SQLite is immediately detected by verify_audit_chain().
"""

import sqlite3
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.storage import Storage, DB_FILE
from app.models.schemas import AuditEvent, DecisionOutcome

client = TestClient(app)
DEV_TOKEN = "tg_agent_dev_token_2026"
AUTH_HEADERS = {"Authorization": f"Bearer {DEV_TOKEN}"}


def test_audit_hash_chain_linking_and_verification():
    """Verifies that audit events form a continuous cryptographic hash chain."""
    storage = Storage()

    # 1. Dispatch two tool calls through the gateway
    resp1 = client.post(
        "/api/v1/agent/dispatch",
        json={
            "agent_id": "readonly_agent",
            "tool_name": "read_file",
            "arguments": {"path": "public/company_handbook.txt"},
        },
        headers=AUTH_HEADERS,
    )
    assert resp1.status_code == 200
    ev1_id = resp1.json()["audit_event_id"]

    resp2 = client.post(
        "/api/v1/agent/dispatch",
        json={
            "agent_id": "standard_agent",
            "tool_name": "query_database",
            "arguments": {"query": "SELECT * FROM products LIMIT 1"},
        },
        headers=AUTH_HEADERS,
    )
    assert resp2.status_code == 200
    ev2_id = resp2.json()["audit_event_id"]

    # 2. Check storage rows
    events = storage.list_audit_events(limit=5)
    ev2 = next((e for e in events if e.event_id == ev2_id), None)
    ev1 = next((e for e in events if e.event_id == ev1_id), None)

    assert ev1 is not None and ev1.event_hash is not None
    assert ev2 is not None and ev2.event_hash is not None
    # Predecessor linking: ev2 must link to its predecessor
    assert ev2.previous_event_hash is not None

    # 3. Verify intact audit chain
    verif = storage.verify_audit_chain()
    assert verif.is_valid is True
    assert verif.verified_events > 0
    assert "intact" in verif.message.lower() or "verified" in verif.message.lower()


def test_tamper_detection_in_audit_chain():
    """
    Verifies that if an attacker modifies an audit record directly in SQLite,
    the hash-chain verification detects the tamper and identifies the compromised record.
    """
    storage = Storage()

    # Create a fresh audit event to tamper with
    resp = client.post(
        "/api/v1/agent/dispatch",
        json={
            "agent_id": "standard_agent",
            "tool_name": "send_email",
            "arguments": {"to": "tamper-test@evil.com", "body": "classified"},
        },
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 200
    ev_id = resp.json()["audit_event_id"]

    # Before tampering, chain is valid
    pre_verif = storage.verify_audit_chain()
    assert pre_verif.is_valid is True

    # Attacker modifies the decision in SQLite from 'deny' to 'allow'
    conn = sqlite3.connect(str(DB_FILE))
    cursor = conn.cursor()
    cursor.execute("UPDATE audit_events SET decision = 'allow' WHERE event_id = ?", (ev_id,))
    conn.commit()
    conn.close()

    # Verification MUST now fail and flag the tampered event!
    post_verif = storage.verify_audit_chain()
    assert post_verif.is_valid is False
    assert post_verif.tampered_event_id == ev_id
    assert "signature mismatch" in post_verif.message or "modified" in post_verif.message

    # Restore the decision so DB remains clean
    conn = sqlite3.connect(str(DB_FILE))
    cursor = conn.cursor()
    cursor.execute("UPDATE audit_events SET decision = 'deny' WHERE event_id = ?", (ev_id,))
    conn.commit()
    conn.close()

    # Re-verify that restoring integrity passes
    restored_verif = storage.verify_audit_chain()
    assert restored_verif.is_valid is True
