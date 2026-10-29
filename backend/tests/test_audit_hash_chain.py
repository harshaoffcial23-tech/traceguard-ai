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
    assert "mismatch" in post_verif.message or "modified" in post_verif.message

    # Restore the decision so DB remains clean
    conn = sqlite3.connect(str(DB_FILE))
    cursor = conn.cursor()
    cursor.execute("UPDATE audit_events SET decision = 'deny' WHERE event_id = ?", (ev_id,))
    conn.commit()
    conn.close()

    # Re-verify that restoring integrity passes
    restored_verif = storage.verify_audit_chain()
    assert restored_verif.is_valid is True


def test_api_verify_chain_auth_behavior():
    """
    Verifies the HTTP API endpoint /api/audit/verify-chain:
    1. Unauthenticated guest caller can verify public ledger integrity (200 OK).
    2. Authenticated agent caller with valid dev key can verify ledger integrity (200 OK).
    3. Caller with explicit invalid/forged bearer token receives 401 Unauthorized.
    """
    # 1. Unauthenticated / guest caller (no headers)
    resp_anon = client.get("/api/audit/verify-chain")
    assert resp_anon.status_code == 200
    data_anon = resp_anon.json()
    assert "is_valid" in data_anon
    assert "verified_events" in data_anon
    assert data_anon["is_valid"] is True

    # 2. Authenticated caller with valid dev agent token
    resp_auth = client.get("/api/audit/verify-chain", headers=AUTH_HEADERS)
    assert resp_auth.status_code == 200
    assert resp_auth.json()["is_valid"] is True

    # 3. Caller with invalid token explicitly supplied must be rejected with 401
    resp_invalid = client.get(
        "/api/audit/verify-chain",
        headers={"Authorization": "Bearer invalid_forged_token_xyz_999"},
    )
    assert resp_invalid.status_code == 401
    assert "detail" in resp_invalid.json()


def test_audit_chain_detects_deletion_of_record():
    """
    Verifies that deleting a record from the middle of the audit chain
    causes verify_audit_chain() to detect a predecessor hash mismatch.
    """
    storage = Storage()

    # Dispatch 3 consecutive tool calls to create a 3-link chain
    ids = []
    for i in range(3):
        r = client.post(
            "/api/v1/agent/dispatch",
            json={
                "agent_id": "readonly_agent",
                "tool_name": "read_file",
                "arguments": {"path": "public/company_handbook.txt"},
                "correlation_id": f"del_test_{i}",
            },
            headers=AUTH_HEADERS,
        )
        assert r.status_code == 200
        ids.append(r.json()["audit_event_id"])

    # Baseline: chain is valid
    assert storage.verify_audit_chain().is_valid is True

    # Temporarily extract the middle record with its exact SQLite rowid
    conn = sqlite3.connect(str(DB_FILE))
    cursor = conn.cursor()
    cursor.execute("SELECT rowid, * FROM audit_events WHERE event_id = ?", (ids[1],))
    row_with_rowid = cursor.fetchone()
    orig_rowid = row_with_rowid[0]
    middle_row = row_with_rowid[1:]

    # Delete the middle record
    cursor.execute("DELETE FROM audit_events WHERE event_id = ?", (ids[1],))
    conn.commit()
    conn.close()

    # Verification MUST fail because event 3's predecessor hash won't match event 1's hash
    del_verif = storage.verify_audit_chain()
    assert del_verif.is_valid is False
    assert "predecessor hash mismatch" in del_verif.message or "broken" in del_verif.message

    # Restore deleted record with its original rowid so database order remains intact
    conn = sqlite3.connect(str(DB_FILE))
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(audit_events)")
    col_names = [col[1] for col in cursor.fetchall()]
    cols_str = "rowid, " + ", ".join(col_names)
    placeholders = ", ".join(["?"] * (len(col_names) + 1))
    cursor.execute(f"INSERT INTO audit_events ({cols_str}) VALUES ({placeholders})", (orig_rowid, *middle_row))
    conn.commit()
    conn.close()

    # Re-verify that chain is restored
    assert storage.verify_audit_chain().is_valid is True


def test_empty_audit_chain_handling(tmp_path):
    """Verifies that an empty database returns is_valid=True with 0 events."""
    from app.db.storage import Storage
    db_path = tmp_path / "test_empty_chain.db"
    temp_storage = Storage(db_path=db_path)

    verif = temp_storage.verify_audit_chain()
    assert verif.is_valid is True
    assert verif.total_events == 0
    assert verif.verified_events == 0
    assert "empty" in verif.message.lower()


def test_audit_chain_detects_deletion_of_first_record():
    """
    Verifies that deleting the genesis / first record from the audit chain
    causes verify_audit_chain() to detect that the new first record's
    predecessor hash does not match the expected genesis hash ('0'*64).
    """
    storage = Storage()
    conn = sqlite3.connect(str(DB_FILE))
    cursor = conn.cursor()
    cursor.execute("SELECT rowid, * FROM audit_events WHERE event_hash IS NOT NULL ORDER BY rowid ASC LIMIT 1")
    first_row = cursor.fetchone()
    if not first_row:
        conn.close()
        pytest.skip("No audit events in DB to test first record deletion")

    orig_rowid = first_row[0]
    first_data = first_row[1:]

    # Delete first record
    cursor.execute("DELETE FROM audit_events WHERE rowid = ?", (orig_rowid,))
    conn.commit()
    conn.close()

    try:
        verif = storage.verify_audit_chain()
        # If there are remaining records, chain MUST be detected as broken
        if verif.total_events > 0:
            assert verif.is_valid is False
            assert "predecessor hash mismatch" in verif.message or "broken" in verif.message
    finally:
        # Restore first record with original rowid
        conn = sqlite3.connect(str(DB_FILE))
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(audit_events)")
        col_names = [col[1] for col in cursor.fetchall()]
        cols_str = "rowid, " + ", ".join(col_names)
        placeholders = ", ".join(["?"] * (len(col_names) + 1))
        cursor.execute(f"INSERT INTO audit_events ({cols_str}) VALUES ({placeholders})", (orig_rowid, *first_data))
        conn.commit()
        conn.close()

    # Re-verify that chain is restored
    assert storage.verify_audit_chain().is_valid is True


def test_audit_chain_detects_record_reordering():
    """
    Verifies that swapping the position (reordering) of two adjacent records
    causes verify_audit_chain() to immediately fail.
    """
    storage = Storage()
    conn = sqlite3.connect(str(DB_FILE))
    cursor = conn.cursor()
    cursor.execute("SELECT rowid, event_id FROM audit_events WHERE event_hash IS NOT NULL ORDER BY rowid ASC LIMIT 2")
    rows = cursor.fetchall()
    if len(rows) < 2:
        conn.close()
        pytest.skip("Need at least 2 audit events to test reordering")

    row1_id, ev1_id = rows[0]
    row2_id, ev2_id = rows[1]

    # Swap event_id of the two rows
    cursor.execute("UPDATE audit_events SET event_id = 'TEMP_SWAP' WHERE rowid = ?", (row1_id,))
    cursor.execute("UPDATE audit_events SET event_id = ? WHERE rowid = ?", (ev1_id, row2_id))
    cursor.execute("UPDATE audit_events SET event_id = ? WHERE rowid = ?", (ev2_id, row1_id))
    conn.commit()
    conn.close()

    try:
        verif = storage.verify_audit_chain()
        assert verif.is_valid is False
    finally:
        # Swap back
        conn = sqlite3.connect(str(DB_FILE))
        cursor = conn.cursor()
        cursor.execute("UPDATE audit_events SET event_id = 'TEMP_SWAP' WHERE rowid = ?", (row1_id,))
        cursor.execute("UPDATE audit_events SET event_id = ? WHERE rowid = ?", (ev2_id, row2_id))
        cursor.execute("UPDATE audit_events SET event_id = ? WHERE rowid = ?", (ev1_id, row1_id))
        conn.commit()
        conn.close()

    assert storage.verify_audit_chain().is_valid is True
