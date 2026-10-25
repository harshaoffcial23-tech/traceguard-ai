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
        and NO deny rule triggers.
        """
        tool_name = request.tool_name
        args = request.arguments or {}
        violations: List[str] = []
        matched_rules: List[str] = []

        # 0. Basic Validation: Valid tool name
        valid_tools = {"read_file", "query_database", "send_email"}
        if tool_name not in valid_tools:
            return GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.DENY,
                policy_id=self.policy_set.id,
                policy_name=self.policy_set.name,
                reason=f"Tool '{tool_name}' is not a registered protected tool.",
                violations=[f"Unregistered tool: '{tool_name}'"],
                matched_rules=["VALIDATE-TOOL-NAME"],
            )

        # 1. Deny Rules Evaluation (Priority: Deny rules override allow rules)
        # Sort enabled rules by priority (ascending: lower number = higher priority)
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
            reason="Deny-by-default: No explicit policy rule permitted this tool invocation.",
            violations=[f"No matching ALLOW rule for tool '{tool_name}' with given arguments."],
            matched_rules=matched_rules,
        )

    def _check_rule_match(self, rule: PolicyRule, request: ToolInvocationRequest) -> Tuple[bool, str]:
        ctype = rule.condition_type
        params = rule.parameters
        args = request.arguments or {}

        # Path Traversal Check
        if ctype == "path_traversal_check":
            path = str(args.get("path", ""))
            if ".." in path or "/.." in path or "\\.." in path or path.startswith("/") or path.startswith("\\"):
                return True, f"Policy violation: Directory traversal pattern detected in path '{path}'"
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
            query = str(args.get("query", "")).upper()
            disallowed = params.get("keywords", ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "ATTACH", "EXEC"])
            for kw in disallowed:
                # Use word boundary
                if re.search(r"\b" + re.escape(kw) + r"\b", query):
                    return True, f"Policy violation: SQL statement contains disallowed mutation keyword '{kw}'"
            return False, ""

        # SQL Allowed Tables Whitelist
        elif ctype == "sql_table_whitelist":
            query = str(args.get("query", "")).lower()
            allowed_tables = set(t.lower() for t in params.get("allowed_tables", []))
            protected_tables = set(t.lower() for t in params.get("protected_tables", ["user_profiles", "api_tokens"]))

            # Check if any protected table is mentioned
            for p_table in protected_tables:
                if re.search(r"\b" + re.escape(p_table) + r"\b", query):
                    return True, f"Policy violation: Query targets confidential table '{p_table}'"

            # If rule is an ALLOW rule, verify query targets at least one allowed table
            if rule.action == DecisionOutcome.ALLOW:
                for a_table in allowed_tables:
                    if re.search(r"\b" + re.escape(a_table) + r"\b", query):
                        return True, f"Query accesses permitted table '{a_table}'"
                return False, ""

            return False, ""

        # Email Domain Whitelist / Restriction
        elif ctype == "email_domain_whitelist":
            recipient = str(args.get("to", "")).lower().strip()
            allowed_domains = params.get("allowed_domains", [])
            is_allowed = any(recipient.endswith(d.lower()) for d in allowed_domains)

            if rule.action == DecisionOutcome.DENY:
                # Deny rule triggers if NOT in allowed domains
                if not is_allowed:
                    return True, f"Policy violation: Email recipient '{recipient}' is not within authorized domains {allowed_domains}"
                return False, ""
            else:
                # Allow rule triggers if matches allowed domain
                if is_allowed:
                    return True, f"Email recipient '{recipient}' matches authorized domain list"
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

        # Heuristic Prompt Injection Marker (English, Telugu, Hindi, Tamil, Code-mixed)
        elif ctype == "prompt_injection_guard":
            prompt = str(request.user_prompt or "")
            body = str(args.get("body", ""))
            combined = f"{prompt} {body}".lower()
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
        ],
    )
