"""
TraceGuard AI Policy Engine.
Implements zero-trust, deny-by-default authorization for all AI tool invocations.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple
from app.models.schemas import DecisionOutcome, GatewayDecision, PolicyRule, PolicySet, ToolInvocationRequest


class PolicyEngine:
    """Evaluates proposed tool invocations against active policy sets."""

    def __init__(self, policy_set: Optional[PolicySet] = None):
        self.policy_set = policy_set or get_default_strict_policy_set()

    def set_policy_set(self, policy_set: PolicySet) -> None:
        self.policy_set = policy_set

    def evaluate(self, request: ToolInvocationRequest) -> GatewayDecision:
        """
        Evaluate a tool invocation request.
        Zero-trust principle: Deny-by-default unless an active rule explicitly allows
        and NO deny rule triggers. Fails closed on any evaluation error.
        """
        try:
            tool_name = request.tool_name
            args = request.arguments or {}
            violations: List[str] = []
            matched_rules: List[str] = []

            # 0. Basic Validation: Valid tool name
            valid_tools = {"read_file", "query_database", "send_email", "web_search"}
            if tool_name not in valid_tools:
                return GatewayDecision(
                    allowed=False,
                    decision=DecisionOutcome.DENY,
                    policy_id=self.policy_set.id,
                    policy_name=self.policy_set.name,
                    rule_id="VALIDATE_TOOL_NAME",
                    reason=f"Tool '{tool_name}' is not a registered protected tool.",
                    violations=[f"Unregistered tool: '{tool_name}'"],
                    matched_rules=["VALIDATE-TOOL-NAME"],
                )

            # 1. Deny Rules Evaluation (Priority: Deny rules override allow rules)
            enabled_rules = sorted(
                [r for r in self.policy_set.rules if r.enabled and (r.tool == tool_name or r.tool == "*")],
                key=lambda r: r.priority,
            )

            explicitly_allowed = False
            allow_rule_matched: Optional[PolicyRule] = None

            for rule in enabled_rules:
                matched, reason = self._check_rule_match(rule, request)
                if matched:
                    matched_rules.append(rule.id)
                    if rule.action == DecisionOutcome.DENY:
                        violations.append(reason)
                        return GatewayDecision(
                            allowed=False,
                            decision=DecisionOutcome.DENY,
                            policy_id=self.policy_set.id,
                            policy_name=self.policy_set.name,
                            rule_id=rule.id,
                            reason=reason,
                            violations=violations,
                            matched_rules=matched_rules,
                        )
                    elif rule.action == DecisionOutcome.ALLOW:
                        explicitly_allowed = True
                        allow_rule_matched = rule

            # 2. Check if explicitly allowed
            if explicitly_allowed and allow_rule_matched:
                return GatewayDecision(
                    allowed=True,
                    decision=DecisionOutcome.ALLOW,
                    policy_id=self.policy_set.id,
                    policy_name=self.policy_set.name,
                    rule_id=allow_rule_matched.id,
                    reason=f"Action permitted by policy rule '{allow_rule_matched.name}'",
                    violations=[],
                    matched_rules=matched_rules,
                )

            # 3. Deny by default
            return GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.DENY,
                policy_id=self.policy_set.id,
                policy_name=self.policy_set.name,
                rule_id="DEFAULT_DENY",
                reason="Deny-by-default: No explicit policy rule permitted this tool invocation.",
                violations=[f"No matching ALLOW rule for tool '{tool_name}' with given arguments."],
                matched_rules=matched_rules,
            )
        except Exception as e:
            # Critical Security Invariant: Fail Closed
            return GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.DENY,
                policy_id=self.policy_set.id if self.policy_set else "unknown",
                policy_name=self.policy_set.name if self.policy_set else "unknown",
                rule_id="EVALUATION_ERROR_FAIL_CLOSED",
                reason=f"Security Gateway fail-closed: Internal policy evaluation error: {str(e)}",
                violations=[f"Policy evaluation failure: {str(e)}"],
                matched_rules=["FAIL-CLOSED-ON-EXCEPTION"],
            )

    def _check_rule_match(self, rule: PolicyRule, request: ToolInvocationRequest) -> Tuple[bool, str]:
        ctype = rule.condition_type
        params = rule.parameters
        args = request.arguments or {}

        # Path Traversal Check
        if ctype == "path_traversal_check":
            import urllib.parse
            raw_path = str(args.get("path", ""))
            decoded_path = urllib.parse.unquote(raw_path)
            if (
                ".." in raw_path
                or ".." in decoded_path
                or "/.." in raw_path
                or "\\.." in raw_path
                or raw_path.startswith("/")
                or raw_path.startswith("\\")
                or decoded_path.startswith("/")
                or decoded_path.startswith("\\")
                or "\x00" in raw_path
            ):
                return True, f"Policy violation: Directory traversal pattern detected in path '{raw_path}'"
            return False, ""

        # Path Prefix Blacklist
        elif ctype == "path_prefix_deny":
            path = str(args.get("path", "")).strip().lstrip("/\\")
            denied_prefixes = params.get("prefixes", [])
            for prefix in denied_prefixes:
                if path.startswith(prefix):
                    return True, f"Policy violation: Access to protected path prefix '{prefix}' is forbidden."
            return False, ""

        # Path Prefix Whitelist
        elif ctype == "path_prefix_allow":
            path = str(args.get("path", "")).strip().lstrip("/\\")
            allowed_prefixes = params.get("prefixes", [])
            for prefix in allowed_prefixes:
                if path.startswith(prefix):
                    return True, f"Path '{path}' satisfies allowed prefix '{prefix}'."
            return False, ""

        # SQL Destructive / Mutation Disallowed Keywords
        elif ctype == "sql_disallowed_keywords":
            query = str(args.get("query", ""))
            # Strip SQL block and line comments to avoid comment-masking bypasses
            clean_query = re.sub(r"/\*.*?\*/", " ", query, flags=re.DOTALL)
            clean_query = re.sub(r"--[^\r\n]*", " ", clean_query).upper()
            disallowed = params.get("keywords", ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "ATTACH", "EXEC", "REPLACE", "TRUNCATE"])
            for kw in disallowed:
                if re.search(r"\b" + re.escape(kw) + r"\b", clean_query):
                    return True, f"Policy violation: SQL statement contains disallowed mutation keyword '{kw}'"
            return False, ""

        # SQL Allowed Tables Whitelist (Strict Clause Extraction & String Literal Stripping)
        elif ctype == "sql_table_whitelist":
            query_raw = str(args.get("query", ""))

            # Strip SQL comments first
            clean_query = re.sub(r"/\*.*?\*/", " ", query_raw, flags=re.DOTALL)
            clean_query = re.sub(r"--[^\r\n]*", " ", clean_query)

            # Strip string literals ('...') so attackers cannot embed table names in string literals
            query_no_literals = re.sub(r"'[^']*'", "''", clean_query).lower()

            allowed_tables = set(t.lower() for t in params.get("allowed_tables", []))
            protected_tables = set(t.lower() for t in params.get("protected_tables", ["user_profiles", "api_tokens"]))
            system_tables = {"sqlite_master", "sqlite_schema", "sqlite_temp_master", "sqlite_sequence"}

            # 1. Deny check for confidential or system tables
            for p_table in (protected_tables | system_tables):
                if re.search(r"\b" + re.escape(p_table) + r"\b", query_no_literals):
                    return True, f"Policy violation: Query targets confidential table '{p_table}'"

            # Reject stacked / multi-statement queries (semicolon followed by non-whitespace statements)
            if re.search(r";\s*[a-zA-Z]", query_no_literals):
                return True, "Policy violation: Stacked/multi-statement queries are forbidden."

            # 2. Extract referenced tables strictly from FROM and JOIN clauses
            from_matches = re.findall(r"\bfrom\s+([a-zA-Z0-9_\"]+)", query_no_literals)
            join_matches = re.findall(r"\bjoin\s+([a-zA-Z0-9_\"]+)", query_no_literals)
            referenced_tables = {tbl.strip('"[]`').lower() for tbl in (from_matches + join_matches)}

            # If rule is an ALLOW rule, verify query targets at least one allowed table and only allowed tables
            if rule.action == DecisionOutcome.ALLOW:
                if referenced_tables and referenced_tables.issubset(allowed_tables):
                    tables_str = ", ".join(sorted(list(referenced_tables)))
                    return True, f"Query accesses permitted table(s) '{tables_str}'"
                return False, ""

            return False, ""

        # Email Domain Whitelist / Restriction (Standard RFC 5322 Parsing)
        elif ctype == "email_domain_whitelist":
            import email.utils
            raw_to = str(args.get("to", "")).strip()
            allowed_domains = [d.lower() for d in params.get("allowed_domains", [])]

            # Reject header injection in recipient
            if "\r" in raw_to or "\n" in raw_to:
                return True, "Policy violation: CRLF header injection detected in email recipient."

            # Use standard library RFC 5322 parser
            parsed_addresses = email.utils.getaddresses([raw_to])

            # If nothing parsed or any address is empty or lacks '@'
            if not parsed_addresses or any(not addr or "@" not in addr for _, addr in parsed_addresses):
                return True, f"Policy violation: Malformed or unparseable recipient address in '{raw_to}'"

            # Wildcard domain check
            if "*" in allowed_domains or "@*" in allowed_domains:
                all_allowed = True
            else:
                all_allowed = all(
                    any(addr.lower().endswith(d) for d in allowed_domains)
                    for _, addr in parsed_addresses
                )

            if rule.action == DecisionOutcome.DENY:
                # Deny rule triggers if ANY recipient is not authorized
                if not all_allowed:
                    return True, f"Policy violation: Email recipient '{raw_to}' is not within authorized domains {allowed_domains}"
                return False, ""
            else:
                # Allow rule triggers only if ALL recipients are authorized
                if all_allowed:
                    return True, f"All email recipients in '{raw_to}' match authorized domain list {allowed_domains}"
                return False, ""

        # Email PII / Secret Exfiltration Prevention
        elif ctype == "email_content_inspection":
            body = str(args.get("body", ""))
            subject = str(args.get("subject", ""))
            combined = f"{subject} {body}"

            from app.gateway.redactor import inspect_data_exposure
            exposure = inspect_data_exposure(combined)
            if exposure.exposure_detected:
                categories = ", ".join(exposure.exposed_categories)
                return True, f"Policy violation: Attempted data exfiltration. Email content contains {categories}."
            return False, ""

        # Heuristic Prompt Injection Marker with Benign Security Analysis Exemption
        elif ctype == "prompt_injection_guard":
            # 1. Exempt if in explicit security analysis mode or quoting for research
            context = request.context or {}
            if context.get("security_analysis_mode") or context.get("analysis_mode"):
                return False, ""

            prompt = str(request.user_prompt or "")
            body = str(args.get("body", ""))
            combined = f"{prompt} {body}".lower()

            # Benign inquiry phrases that quote malicious text for verification
            benign_markers = [
                "benign analysis",
                "cve analysis",
                "analyzing payload",
                "security audit quote",
                "quoted below for testing",
                "explain the security risk of",
            ]
            if any(m in combined for m in benign_markers):
                return False, ""
            signatures = params.get("signatures", [
                "ignore previous instructions",
                "disregard prior",
                "system override",
                "override instruction",
                "system advisory",
                "సిస్టమ్ ఓవర్‌రైడ్",
                "భద్రతా నియమాలు",
                "విస్మరించండి",
                "సిస్టమ్ ఓవర్ రైడ్",
                "సిస్టం ఓవర్ రైడ్",
                "సిస్టమ్ బైపాస్",
                "పాస్‌వర్డ్‌లు",
                "రహస్య ఫైల్",
                "सिस्टम ओवरराइड",
                "सुरक्षा अनदेखा",
                "कमांड ओवरराइड",
                "पासवर्ड निकालें",
                "प्रतिबंधित फ़ाइल",
                "கணினி மேலெழுதல்",
                "பாதுகாப்பு விதிகளை புறக்கணிக்கவும்",
                "ரகசியங்களை படிக்க",
                "system override karo",
                "system override pannu",
                "system override chesi",
                "credentials nikal",
                "irukkura keys",
                "api passwords theesi",
            ])
            for sig in signatures:
                if sig.lower() in combined:
                    return True, f"Policy violation: Prompt injection signature detected: '{sig}'"
            return False, ""

        # Web Search Query Inspection (Prevent data exfiltration via external search)
        elif ctype == "web_search_content_inspection":
            query = str(args.get("query", ""))
            from app.gateway.redactor import inspect_data_exposure
            exposure = inspect_data_exposure(query)
            if exposure.exposure_detected:
                categories = ", ".join(exposure.exposed_categories)
                return True, f"Policy violation: Attempted data exfiltration via search query. Query contains {categories}."
            return False, ""

        # Web Search General Allow
        elif ctype == "web_search_general_allow":
            query = str(args.get("query", "")).strip()
            if query:
                return True, f"Web search query '{query[:40]}' permitted for external research."
            return False, ""

        return False, ""


def get_default_strict_policy_set() -> PolicySet:
    """Standard hardened security policy set for TraceGuard AI."""
    return PolicySet(
        id="policy_strict_enterprise_v1",
        name="Enterprise Strict Zero-Trust (Default)",
        description="Deny-by-default with strict path confinement, table access control, and email domain whitelisting.",
        is_active=True,
        default_action=DecisionOutcome.DENY,
        rules=[
            PolicyRule(
                id="RULE-INJECTION-01-HEURISTIC-DENY",
                name="Block Known Adversarial Prompt Injections",
                description="Deny actions triggered by direct jailbreaks, system overrides, or multilingual bypass signatures.",
                enabled=True,
                priority=5,
                tool="*",
                action=DecisionOutcome.DENY,
                condition_type="prompt_injection_guard",
            ),
            PolicyRule(
                id="RULE-FILE-01-TRAVERSAL-DENY",
                name="Block Path Traversal",
                description="Deny any file path containing relative directory traversal or root escapes.",
                enabled=True,
                priority=10,
                tool="read_file",
                action=DecisionOutcome.DENY,
                condition_type="path_traversal_check",
            ),
            PolicyRule(
                id="RULE-FILE-02-RESTRICTED-DENY",
                name="Block Restricted Directory Access",
                description="Deny access to credentials, PII exports, and secret directories.",
                enabled=True,
                priority=20,
                tool="read_file",
                action=DecisionOutcome.DENY,
                condition_type="path_prefix_deny",
                parameters={"prefixes": ["restricted/", "restricted\\", ".env"]},
            ),
            PolicyRule(
                id="RULE-FILE-03-PUBLIC-ALLOW",
                name="Allow Public & Internal Docs",
                description="Allow read-only access to vetted public and internal documentation.",
                enabled=True,
                priority=50,
                tool="read_file",
                action=DecisionOutcome.ALLOW,
                condition_type="path_prefix_allow",
                parameters={"prefixes": ["public/", "internal/", "external_incoming/"]},
            ),
            PolicyRule(
                id="RULE-SQL-01-MUTATION-DENY",
                name="Block SQL Data Modification",
                description="Deny all SQL statements attempting DROP, DELETE, UPDATE, INSERT, or ALTER.",
                enabled=True,
                priority=10,
                tool="query_database",
                action=DecisionOutcome.DENY,
                condition_type="sql_disallowed_keywords",
                parameters={"keywords": ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "ATTACH", "EXEC", "REPLACE"]},
            ),
            PolicyRule(
                id="RULE-SQL-02-CONFIDENTIAL-DENY",
                name="Block Confidential Tables Access",
                description="Deny queries that attempt to read user_profiles or api_tokens tables.",
                enabled=True,
                priority=20,
                tool="query_database",
                action=DecisionOutcome.DENY,
                condition_type="sql_table_whitelist",
                parameters={"protected_tables": ["user_profiles", "api_tokens"]},
            ),
            PolicyRule(
                id="RULE-SQL-03-CATALOG-ALLOW",
                name="Allow Read Queries to Public Catalog",
                description="Allow SELECT queries on products and faq tables.",
                enabled=True,
                priority=50,
                tool="query_database",
                action=DecisionOutcome.ALLOW,
                condition_type="sql_table_whitelist",
                parameters={"allowed_tables": ["products", "faq"], "protected_tables": ["user_profiles", "api_tokens"]},
            ),
            PolicyRule(
                id="RULE-EMAIL-01-EXTERNAL-DENY",
                name="Block External Email Destinations",
                description="Deny sending emails to external, unverified, or public domains.",
                enabled=True,
                priority=10,
                tool="send_email",
                action=DecisionOutcome.DENY,
                condition_type="email_domain_whitelist",
                parameters={"allowed_domains": ["@traceguard.internal", "@acmecorp.internal"]},
            ),
            PolicyRule(
                id="RULE-EMAIL-02-EXFIL-CONTENT-DENY",
                name="Block PII and Secret Exfiltration in Emails",
                description="Deny emails containing SSNs, credit cards, or API secrets.",
                enabled=True,
                priority=15,
                tool="send_email",
                action=DecisionOutcome.DENY,
                condition_type="email_content_inspection",
            ),
            PolicyRule(
                id="RULE-EMAIL-03-INTERNAL-ALLOW",
                name="Allow Internal Notifications",
                description="Allow emails addressed strictly to internal personnel.",
                enabled=True,
                priority=50,
                tool="send_email",
                action=DecisionOutcome.ALLOW,
                condition_type="email_domain_whitelist",
                parameters={"allowed_domains": ["@traceguard.internal", "@acmecorp.internal"]},
            ),
            PolicyRule(
                id="RULE-WEB-01-EXFIL-QUERY-DENY",
                name="Block Secret Exfiltration via Web Search Query",
                description="Deny external web search queries that contain detected PII, API tokens, or secrets.",
                enabled=True,
                priority=15,
                tool="web_search",
                action=DecisionOutcome.DENY,
                condition_type="web_search_content_inspection",
            ),
            PolicyRule(
                id="RULE-WEB-02-SEARCH-ALLOW",
                name="Allow Public Research Web Searches",
                description="Allow external web search queries for benign research that do not leak internal data.",
                enabled=True,
                priority=50,
                tool="web_search",
                action=DecisionOutcome.ALLOW,
                condition_type="web_search_general_allow",
            ),
        ],
    )


def get_permissive_policy_set() -> PolicySet:
    """
    Permissive (unhardened) policy set used for comparative benchmarking
    and demonstrating regression/vulnerability exposure.
    """
    return PolicySet(
        id="policy_permissive_v0",
        name="Permissive Unhardened Policy (Demonstration)",
        description="Relaxed rules allowing broad file paths and external email destinations.",
        is_active=False,
        default_action=DecisionOutcome.DENY,
        rules=[
            PolicyRule(
                id="RULE-PERM-FILE-ALLOW",
                name="Allow Any Sandbox File Read",
                description="Allows reading any file in the sandbox, including restricted credentials.",
                enabled=True,
                priority=100,
                tool="read_file",
                action=DecisionOutcome.ALLOW,
                condition_type="path_prefix_allow",
                parameters={"prefixes": ["public/", "internal/", "restricted/", "external_incoming/"]},
            ),
            PolicyRule(
                id="RULE-PERM-SQL-ALLOW",
                name="Allow Any SQL SELECT",
                description="Allows SELECT queries on any table including user_profiles.",
                enabled=True,
                priority=100,
                tool="query_database",
                action=DecisionOutcome.ALLOW,
                condition_type="sql_table_whitelist",
                parameters={"allowed_tables": ["products", "faq", "user_profiles", "api_tokens"]},
            ),
            PolicyRule(
                id="RULE-PERM-EMAIL-ALLOW",
                name="Allow Any Email Destination",
                description="Allows sending email to any external recipient without domain check.",
                enabled=True,
                priority=100,
                tool="send_email",
                action=DecisionOutcome.ALLOW,
                condition_type="email_domain_whitelist",
                parameters={"allowed_domains": ["*"]},
            ),
            PolicyRule(
                id="RULE-PERM-WEB-ALLOW",
                name="Allow Any Web Search",
                description="Allows executing external web searches without query inspection.",
                enabled=True,
                priority=100,
                tool="web_search",
                action=DecisionOutcome.ALLOW,
                condition_type="web_search_general_allow",
            ),
        ],
    )
