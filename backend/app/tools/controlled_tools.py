"""
Controlled tool implementations for TraceGuard AI security lab.
Provides safe, sandboxed implementations of:
- read_file
- query_database
- send_email
"""

from __future__ import annotations
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from app.models.schemas import ToolExecutionResult


# Resolve sandbox base paths
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
FILES_SANDBOX_DIR = (BACKEND_DIR / "data" / "sandbox" / "files").resolve()
DB_SANDBOX_PATH = (BACKEND_DIR / "data" / "sandbox" / "sandbox_db.sqlite").resolve()

# In-memory mock outbox for send_email
OUTBOX_LOG: List[Dict[str, Any]] = []


class SandboxedTools:
    """Encapsulates sandboxed tool executions."""

    @staticmethod
    def read_file(path: str) -> ToolExecutionResult:
        """
        Controlled read_file tool.
        Only resolves within FILES_SANDBOX_DIR.
        """
        try:
            if not path:
                return ToolExecutionResult(
                    executed=True,
                    success=False,
                    error="Argument 'path' is required.",
                )

            # Prevent path traversal tricks
            clean_path = path.strip().lstrip("/\\")
            resolved_path = (FILES_SANDBOX_DIR / clean_path).resolve()

            # Ensure resolved path is strictly within the sandbox
            try:
                resolved_path.relative_to(FILES_SANDBOX_DIR)
            except ValueError:
                return ToolExecutionResult(
                    executed=True,
                    success=False,
                    error=f"Access denied: Path '{path}' escapes controlled sandbox root.",
                )

            if not resolved_path.exists():
                return ToolExecutionResult(
                    executed=True,
                    success=False,
                    error=f"File not found: '{path}' in sandbox.",
                )

            if not resolved_path.is_file():
                return ToolExecutionResult(
                    executed=True,
                    success=False,
                    error=f"Target is not a regular file: '{path}'.",
                )

            with open(resolved_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            return ToolExecutionResult(
                executed=True,
                success=True,
                output=content,
                metadata={"file_size_bytes": len(content), "path": path},
            )
        except Exception as e:
            return ToolExecutionResult(
                executed=True,
                success=False,
                error=f"read_file execution error: {str(e)}",
            )

    @staticmethod
    def query_database(query: str) -> ToolExecutionResult:
        """
        Controlled query_database tool.
        Executes query against the synthetic SQLite sandbox.
        """
        try:
            if not query or not query.strip():
                return ToolExecutionResult(
                    executed=True,
                    success=False,
                    error="Argument 'query' is required.",
                )

            if not DB_SANDBOX_PATH.exists():
                from app.tools.db_init import init_sandbox_db
                init_sandbox_db(DB_SANDBOX_PATH)

            # Enforce read-only SQLite engine mode for SELECT / catalog queries
            db_uri = f"file:{DB_SANDBOX_PATH.as_posix()}?mode=ro"
            try:
                conn = sqlite3.connect(db_uri, uri=True)
            except sqlite3.OperationalError:
                # Fallback to standard path if URI mode unsupported on platform
                conn = sqlite3.connect(str(DB_SANDBOX_PATH))

            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(query)
            if query.strip().upper().startswith("SELECT") or query.strip().upper().startswith("PRAGMA"):
                rows = cursor.fetchall()
                result = [dict(row) for row in rows]
                row_count = len(result)
            else:
                conn.commit()
                row_count = cursor.rowcount
                result = {"affected_rows": row_count}

            conn.close()
            return ToolExecutionResult(
                executed=True,
                success=True,
                output=result,
                metadata={"row_count": row_count, "query": query},
            )
        except Exception as e:
            return ToolExecutionResult(
                executed=True,
                success=False,
                error=f"Database execution error: {str(e)}",
            )

    @staticmethod
    def send_email(to: str, subject: str, body: str) -> ToolExecutionResult:
        """
        Controlled send_email tool.
        Records sent emails to an internal outbox without external network transmission.
        """
        try:
            if not to:
                return ToolExecutionResult(
                    executed=True,
                    success=False,
                    error="Argument 'to' is required.",
                )

            message_id = f"msg_{uuid.uuid4().hex[:12]}"
            email_record = {
                "message_id": message_id,
                "to": to,
                "subject": subject or "(No Subject)",
                "body": body or "",
                "status": "dispatched_to_mock_outbox",
            }
            OUTBOX_LOG.append(email_record)

            return ToolExecutionResult(
                executed=True,
                success=True,
                output={
                    "message_id": message_id,
                    "status": "delivered_to_mock_outbox",
                    "recipient": to,
                },
                metadata={"outbox_size": len(OUTBOX_LOG)},
            )
        except Exception as e:
            return ToolExecutionResult(
                executed=True,
                success=False,
                error=f"send_email execution error: {str(e)}",
            )

    @staticmethod
    def web_search(query: str, max_results: int = 3) -> ToolExecutionResult:
        """
        Controlled web_search tool via Tavily API.
        Executes external public domain search.
        Results are strictly tagged as untrusted content.
        """
        try:
            if not query or not str(query).strip():
                return ToolExecutionResult(
                    executed=True,
                    success=False,
                    error="Argument 'query' is required.",
                )

            from app.agents.tavily_adapter import TavilySearchAdapter
            adapter = TavilySearchAdapter()
            search_res = adapter.search(query=str(query).strip(), max_results=max_results)

            if search_res.get("success"):
                return ToolExecutionResult(
                    executed=True,
                    success=True,
                    output=search_res,
                    metadata={
                        "is_untrusted_content": True,
                        "query": query,
                        "is_simulated": search_res.get("is_simulated", False),
                        "results_count": len(search_res.get("results", [])),
                    },
                )
            else:
                return ToolExecutionResult(
                    executed=True,
                    success=False,
                    error=search_res.get("error", "Web search failed"),
                    metadata={"is_untrusted_content": True, "query": query},
                )
        except Exception as e:
            return ToolExecutionResult(
                executed=True,
                success=False,
                error=f"web_search execution error: {str(e)}",
            )


# Tool definitions for tool-use agents (OpenAI / Groq function calling schema)
REGISTERED_TOOLS_SPEC = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file in the accessible sandbox repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path of the file to read (e.g. 'public/company_handbook.txt')",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_database",
            "description": "Execute a SQL query against the system database catalog.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The SQL query to run against the database (e.g. 'SELECT * FROM products')",
                    }
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email message to a specified recipient.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {
                        "type": "string",
                        "description": "Destination email address (e.g. 'helpdesk@traceguard.internal')",
                    },
                    "subject": {
                        "type": "string",
                        "description": "Email subject header",
                    },
                    "body": {
                        "type": "string",
                        "description": "Email body message",
                    },
                },
                "required": ["to", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Execute a controlled external web search query via Tavily to retrieve public domain research.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query string (e.g. 'SIEM zero trust guidelines')",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of search results to return (1-5)",
                    },
                },
                "required": ["query"],
            },
        },
    },
]


def execute_tool(tool_name: str, arguments: Dict[str, Any]) -> ToolExecutionResult:
    """Direct dispatcher for registered controlled tools."""
    if tool_name == "read_file":
        return SandboxedTools.read_file(path=arguments.get("path", ""))
    elif tool_name == "query_database":
        return SandboxedTools.query_database(query=arguments.get("query", ""))
    elif tool_name == "send_email":
        return SandboxedTools.send_email(
            to=arguments.get("to", ""),
            subject=arguments.get("subject", ""),
            body=arguments.get("body", ""),
        )
    elif tool_name == "web_search":
        return SandboxedTools.web_search(
            query=arguments.get("query", ""),
            max_results=int(arguments.get("max_results", 3)),
        )
    else:
        return ToolExecutionResult(
            executed=False,
            success=False,
            error=f"Unrecognized tool '{tool_name}'",
        )
