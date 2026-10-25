"""
TraceGuard AI - Server-side Tool Schema & Argument Validator.
Enforces strict schema validation, type integrity, and parameter sanitization
prior to security policy evaluation and execution dispatch.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_tool_schema(tool_name: str, arguments: Any) -> Tuple[bool, Optional[str]]:
    """
    Validates tool name and invocation arguments against registered schemas.
    Fails closed on malformed types, missing required arguments, null bytes,
    header injections, or unexpected argument pollution.
    """
    valid_tools = {"read_file", "query_database", "send_email", "web_search"}
    if tool_name not in valid_tools:
        return False, f"Unregistered tool name: '{tool_name}'"

    if not isinstance(arguments, dict):
        return False, f"Malformed tool arguments: Expected JSON object/dict, got {type(arguments).__name__}"

    if tool_name == "read_file":
        return _validate_read_file(arguments)
    elif tool_name == "query_database":
        return _validate_query_database(arguments)
    elif tool_name == "send_email":
        return _validate_send_email(arguments)
    elif tool_name == "web_search":
        return _validate_web_search(arguments)

    return False, f"Unsupported tool schema validator for '{tool_name}'"


def _validate_read_file(args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    # Allowed keys
    allowed_keys = {"path"}
    unexpected = set(args.keys()) - allowed_keys
    if unexpected:
        return False, f"Unexpected argument(s) for read_file: {sorted(list(unexpected))}"

    if "path" not in args:
        return False, "Missing required argument 'path' for read_file."

    path_val = args["path"]
    if not isinstance(path_val, str):
        return False, f"Invalid type for 'path': expected string, got {type(path_val).__name__}."

    if not path_val.strip():
        return False, "Argument 'path' cannot be empty or purely whitespace."

    if "\x00" in path_val:
        return False, "Null byte character detected in file path."

    return True, None


def _validate_query_database(args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    allowed_keys = {"query"}
    unexpected = set(args.keys()) - allowed_keys
    if unexpected:
        return False, f"Unexpected argument(s) for query_database: {sorted(list(unexpected))}"

    if "query" not in args:
        return False, "Missing required argument 'query' for query_database."

    query_val = args["query"]
    if not isinstance(query_val, str):
        return False, f"Invalid type for 'query': expected string, got {type(query_val).__name__}."

    if not query_val.strip():
        return False, "Argument 'query' cannot be empty or purely whitespace."

    if "\x00" in query_val:
        return False, "Null byte character detected in SQL query."

    return True, None


def _validate_send_email(args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    allowed_keys = {"to", "subject", "body"}
    unexpected = set(args.keys()) - allowed_keys
    if unexpected:
        return False, f"Unexpected argument(s) for send_email: {sorted(list(unexpected))}"

    if "to" not in args:
        return False, "Missing required argument 'to' for send_email."

    to_val = args["to"]
    if not isinstance(to_val, str):
        return False, f"Invalid type for 'to': expected string, got {type(to_val).__name__}."

    if not to_val.strip():
        return False, "Argument 'to' cannot be empty or purely whitespace."

    # Prevent header injection / CRLF in recipient
    if "\r" in to_val or "\n" in to_val:
        return False, "CRLF header injection pattern detected in email recipient."

    if "\x00" in to_val:
        return False, "Null byte character detected in email recipient."

    # Parse and validate individual recipients if delimited
    recipients = [r.strip() for r in re.split(r"[,;]", to_val) if r.strip()]
    if not recipients:
        return False, "No valid email recipient address supplied."

    for r in recipients:
        # Strip angle brackets if formatted as Name <email@example.com>
        clean_addr = re.sub(r"^.*<([^>]+)>.*$", r"\1", r).strip()
        if "@" not in clean_addr or len(clean_addr) < 3:
            return False, f"Malformed email address structure: '{clean_addr}'"

    # Validate subject and body types if present
    if "subject" in args:
        subj = args["subject"]
        if subj is not None and not isinstance(subj, str):
            return False, f"Invalid type for 'subject': expected string, got {type(subj).__name__}."
        if isinstance(subj, str) and ("\r" in subj or "\n" in subj):
            return False, "CRLF header injection detected in email subject."
        if isinstance(subj, str) and "\x00" in subj:
            return False, "Null byte detected in email subject."

    if "body" in args:
        body = args["body"]
        if body is not None and not isinstance(body, str):
            return False, f"Invalid type for 'body': expected string, got {type(body).__name__}."
        if isinstance(body, str) and "\x00" in body:
            return False, "Null byte detected in email body."

    return True, None


def _validate_web_search(args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    allowed_keys = {"query", "max_results"}
    unexpected = set(args.keys()) - allowed_keys
    if unexpected:
        return False, f"Unexpected argument(s) for web_search: {sorted(list(unexpected))}"

    if "query" not in args:
        return False, "Missing required argument 'query' for web_search."

    query_val = args["query"]
    if not isinstance(query_val, str):
        return False, f"Invalid type for 'query': expected string, got {type(query_val).__name__}."

    if not query_val.strip():
        return False, "Argument 'query' cannot be empty or purely whitespace."

    if "\x00" in query_val:
        return False, "Null byte character detected in search query."

    if "max_results" in args:
        mr = args["max_results"]
        if not isinstance(mr, int) or mr < 1 or mr > 10:
            return False, "Argument 'max_results' must be an integer between 1 and 10."

    return True, None
