# OPA Rego Policy Bundle for Agent Governance
# Deploy to OPA server: PUT /v1/policies/agent_governance
package agent_governance

import rego.v1

default allow := false

# ── Tool Access by Role ──
tool_allowlist := {
    "analyst":  {"query_database", "web_search", "summarize", "read_file"},
    "reviewer": {"query_database", "web_search", "summarize", "read_file", "write_report", "send_email"},
    "admin":    {"query_database", "web_search", "summarize", "read_file",
                 "write_report", "send_email", "deploy", "manage_users", "execute_script"},
}

# ── Model Access by Unit ──
model_allowlist := {
    "unit_a": {"gpt-4o", "gpt-4o-mini", "claude-3-sonnet"},
    "unit_b": {"gpt-4o-mini", "gemini-1.5-flash"},
    "unit_c": {"gpt-4o", "gpt-4o-mini", "claude-3-sonnet", "gemini-1.5-pro"},
}

# ── MCP Server Access by Unit ──
mcp_server_allowlist := {
    "unit_a": {"github-mcp", "jira-mcp"},
    "unit_b": {"slack-mcp", "confluence-mcp"},
    "unit_c": {"github-mcp", "jira-mcp", "slack-mcp", "confluence-mcp"},
}

# ── Blocked Tools (universal) ──
blocked_tools := {"drop_table", "delete_database", "rm_rf", "execute_shell", "format_disk"}

# ── Main allow rule ──
allow if {
    not input.action.tool in blocked_tools
    input.role in object.keys(tool_allowlist)
    input.action.tool in tool_allowlist[input.role]
}

# Chat/conversation always allowed
allow if {
    input.action.tool in {"chat", "conversation", "message"}
}

# ── Model access rule ──
model_allowed if {
    input.unit in object.keys(model_allowlist)
    input.action.model in model_allowlist[input.unit]
}

model_allowed if {
    input.action.model == ""
}

# ── MCP server access rule ──
mcp_allowed if {
    input.unit in object.keys(mcp_server_allowlist)
    input.action.mcp_server in mcp_server_allowlist[input.unit]
}

mcp_allowed if {
    input.action.mcp_server == ""
}

# ── PII access rule ──
pii_allowed if {
    input.can_access_pii == true
}

pii_allowed if {
    not input.action.contains_pii
}

# ── Combined verdict ──
verdict := {
    "allow": allow,
    "model_allowed": model_allowed,
    "mcp_allowed": mcp_allowed,
    "pii_allowed": pii_allowed,
    "reason": reason,
}

reason := "tool_blocked" if {
    input.action.tool in blocked_tools
}

reason := "tool_not_in_role_allowlist" if {
    not input.action.tool in blocked_tools
    input.role in object.keys(tool_allowlist)
    not input.action.tool in tool_allowlist[input.role]
}

reason := "role_unknown" if {
    not input.role in object.keys(tool_allowlist)
}

reason := "model_not_allowed_for_unit" if {
    input.action.model != ""
    input.unit in object.keys(model_allowlist)
    not input.action.model in model_allowlist[input.unit]
}

reason := "mcp_server_not_allowed" if {
    input.action.mcp_server != ""
    input.unit in object.keys(mcp_server_allowlist)
    not input.action.mcp_server in mcp_server_allowlist[input.unit]
}

reason := "pii_access_denied" if {
    not input.can_access_pii
    input.action.contains_pii
}

reason := "allowed" if {
    allow
    model_allowed
    mcp_allowed
    pii_allowed
}
