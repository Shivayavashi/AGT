"""
AGT Governance Dashboard — Data Models

Pydantic models for Units, Roles, Agents, Policies, and Audit entries.
Uses AGT-style DID identities (did:mesh:<unique-id>).
"""
from __future__ import annotations

import secrets
import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


from agentmesh.identity.agent_id import AgentDID, AgentIdentity

# ── Role ──

class RoleCreate(BaseModel):
    name: str
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_models: list[str] = Field(default_factory=list)
    max_tool_calls_per_minute: int = 60
    can_access_pii: bool = False


class Role(RoleCreate):
    id: str = Field(default_factory=lambda: secrets.token_hex(8))
    unit_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Unit ──

class UnitCreate(BaseModel):
    name: str
    allowed_models: list[str] = Field(default_factory=list)
    mcp_servers_allowed: list[str] = Field(default_factory=list)


class Unit(UnitCreate):
    id: str = Field(default_factory=lambda: secrets.token_hex(8))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Agent ──

class AgentCreate(BaseModel):
    name: str
    unit_id: str
    role_id: str
    sponsor_email: str = "admin@org.com"


class Agent(BaseModel):
    id: str = Field(default_factory=lambda: secrets.token_hex(8))
    name: str
    unit_id: str
    unit_name: str = ""
    role_id: str
    role_name: str = ""
    did: str = ""
    sponsor_email: str = "admin@org.com"
    capabilities: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "active"


# ── Governance Decision ──

class GovernanceVerdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    REQUIRE_APPROVAL = "require_approval"
    TRANSFORM = "transform"


class GovernanceDecision(BaseModel):
    allowed: bool
    verdict: GovernanceVerdict
    reason: str
    rule_name: str = ""
    evaluation_source: str = ""  # "yaml", "opa", "pii", "injection", "mcp"
    evaluation_ms: float = 0.0
    agent_id: str = ""
    action: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Audit Entry ──

class AuditEntry(BaseModel):
    id: str = Field(default_factory=lambda: f"audit_{secrets.token_hex(8)}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str  # policy_check, tool_call, prompt_injection, pii_scan, approval, etc.
    agent_did: str
    agent_name: str = ""
    unit_name: str = ""
    role_name: str = ""
    action: str
    decision: str  # allow, deny, warn, require_approval
    reason: str = ""
    latency_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Merkle chain fields
    entry_hash: str = ""
    prev_hash: str = ""


# ── Chat Message ──

class ChatMessage(BaseModel):
    role: str  # "user" or "assistant"
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    governance: Optional[GovernanceDecision] = None


class ChatRequest(BaseModel):
    agent_id: str
    message: str
    tool_name: Optional[str] = None
    tool_args: dict[str, Any] = Field(default_factory=dict)
    model: Optional[str] = None
    mcp_server: Optional[str] = None


class ChatResponse(BaseModel):
    message: ChatMessage
    governance_decisions: list[GovernanceDecision] = Field(default_factory=list)
    audit_entries: list[AuditEntry] = Field(default_factory=list)


# ── Telemetry ──

class TelemetryEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str
    agent_did: str = ""
    intervention_point: str = ""
    decision: str = ""
    duration_ms: float = 0.0
    policy_id: str = ""
    attributes: dict[str, Any] = Field(default_factory=dict)


# ── Dashboard Stats ──

class DashboardStats(BaseModel):
    total_units: int = 0
    total_roles: int = 0
    total_agents: int = 0
    total_evaluations: int = 0
    total_allowed: int = 0
    total_denied: int = 0
    total_approvals: int = 0
    prompt_injections_blocked: int = 0
    pii_detections: int = 0
    recent_audit: list[AuditEntry] = Field(default_factory=list)
