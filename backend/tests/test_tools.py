"""
Tests for Sandboxed Controlled Tools.
"""

from pathlib import Path
import pytest
from app.tools.controlled_tools import SandboxedTools, execute_tool
from app.tools.db_init import init_sandbox_db


@pytest.fixture(autouse=True)
def setup_db(tmp_path):
    backend_dir = Path(__file__).resolve().parent.parent
    db_file = backend_dir / "data" / "sandbox" / "sandbox_db.sqlite"
    init_sandbox_db(db_file)


def test_read_file_legitimate():
    res = SandboxedTools.read_file("public/company_handbook.txt")
    assert res.executed is True
    assert res.success is True
    assert "TraceGuard AI Employee Handbook" in res.output


def test_read_file_path_traversal():
    res = SandboxedTools.read_file("../../restricted/credentials.env")
    assert res.executed is True
    assert res.success is False
    assert "escapes controlled sandbox" in res.error


def test_read_file_nonexistent():
    res = SandboxedTools.read_file("public/does_not_exist_404.txt")
    assert res.executed is True
    assert res.success is False
    assert "File not found" in res.error


def test_query_database_select():
    res = SandboxedTools.query_database("SELECT * FROM products WHERE price < 1000")
    assert res.executed is True
    assert res.success is True
    assert isinstance(res.output, list)
    assert len(res.output) > 0
    assert "name" in res.output[0]


def test_send_email_mock_outbox():
    res = SandboxedTools.send_email(
        to="helpdesk@traceguard.internal",
        subject="Maintenance Alert",
        body="All systems green.",
    )
    assert res.executed is True
    assert res.success is True
    assert "message_id" in res.output
    assert res.output["recipient"] == "helpdesk@traceguard.internal"


def test_execute_tool_unregistered():
    res = execute_tool("execute_shell_command", {"cmd": "whoami"})
    assert res.executed is False
    assert "Unrecognized tool" in res.error
