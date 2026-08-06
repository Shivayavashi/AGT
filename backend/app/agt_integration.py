"""
AGT Integration Layer
Wires up the ACS SDK, HostAnnotators, OPA Dispatcher, and MAF Kernel.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Mapping
import time

logger = logging.getLogger(__name__)

try:
    from agent_control_specification import AgentControl
except ImportError:
    AgentControl = None
    logger.warning("agent_control_specification not installed (requires Rust). Using fallback mock.")

from agent_os.prompt_injection import PromptInjectionDetector
from agent_os.integrations.base import AdapterExecutionState
from agent_os.integrations.maf_adapter import MAFKernel
from agentmesh.governance.audit import AuditLog, JsonlFileBackend, AuditEntry
from agentmesh.telemetry import bootstrap_otel
from agentmesh.governance.opa import OPAEvaluator

from .models import GovernanceDecision, GovernanceVerdict

Json = Any

# From AGT native patterns
PII_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\b\d{3}[-.]\d{3}[-.]\d{4}\b"),
    re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
]

def text_from(value: Json) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        for key in ("text", "value", "message", "reason"):
            if key in value and isinstance(value[key], str):
                return value[key]
        return json.dumps(value, sort_keys=True)
    return str(value)


class DashboardHostAnnotators:
    """Provides PII and Prompt Injection signals to ACS natively."""
    def __init__(self):
        self.injection_detector = PromptInjectionDetector()

    def dispatch(
        self,
        annotator_name: str,
        annotator_config: Mapping[str, Json],
        preliminary_policy_input: Mapping[str, Json],
    ) -> Json:
        target = preliminary_policy_input["policy_target"]["value"]
        text = text_from(target)
        
        if annotator_name == "prompt_injection":
            injection = self.injection_detector.detect(text)
            if injection["is_injection"]:
                return "prompt_injection"
            return "benign"
            
        if annotator_name == "pii_scan":
            has_pii = any(pattern.search(text) for pattern in PII_PATTERNS)
            if has_pii:
                return "pii_present"
            return "clear"
            
        raise ValueError(f"unknown annotator: {annotator_name}")


class OPADispatcher:
    """Dispatches ACS custom policy to remote OPA server using native AGT OPAEvaluator."""
    def __init__(self, opa_url: str = "http://localhost:8181"):
        # Use native AGT OPAEvaluator
        self.evaluator = OPAEvaluator(mode="remote", opa_url=opa_url)
        self.current_context = {}

    def dispatch(self, policy_id: str, input_data: Mapping[str, Json]) -> dict[str, Any]:
        """Called by ACS when 'opa_agent_policy' is bound."""
        action_type = input_data.get("tool", {}).get("name", "message")
        if input_data.get("intervention_point") == "input":
            action_type = "chat"
            
        opa_input = {
            "agent_id": self.current_context.get("agent_id", "unknown"),
            "unit": self.current_context.get("unit", "unknown").lower().replace(" ", "_"),
            "role": self.current_context.get("role", "unknown").lower(),
            "can_access_pii": self.current_context.get("can_access_pii", False),
            "action": {
                "tool": action_type,
                "params": input_data.get("policy_target", {}).get("value", {}),
                "model": self.current_context.get("model", ""),
                "mcp_server": self.current_context.get("mcp_server", ""),
                "contains_pii": input_data.get("annotations", {}).get("pii_scan") == "pii_present"
            }
        }
        
        # Evaluate using native AGT OPAEvaluator
        decision = self.evaluator.evaluate("data.agent_governance.verdict", opa_input)
        
        if decision.allowed:
            return {"decision": "allow", "reason": "allowed"}
        else:
            # Handle require_approval translation based on OPA reason if needed
            reason = decision.reason or "denied by opa"
            if "requires_approval" in reason:
                return {"decision": "require_approval", "reason": reason}
            return {"decision": "deny", "reason": reason}


class GovernanceRuntime:
    """Wraps ACS, MAFKernel, and Audit logging natively."""
    def __init__(self, manifest_path: str, opa_url: str):
        self.annotators = DashboardHostAnnotators()
        self.opa_dispatcher = OPADispatcher(opa_url)
        
        if AgentControl is not None:
            self.control = AgentControl.from_path(
                manifest_path,
                annotator_dispatcher=self.annotators,
                policy_dispatcher=self.opa_dispatcher
            )
            # The MAF Adapter intercepts the agent
            self.maf_kernel = MAFKernel(runtime=self.control)
        else:
            self.control = None
            self.maf_kernel = None
            
        # Setup Audit
        self.audit_log = AuditLog(backend=JsonlFileBackend("audit_log.jsonl"))
        
        # Bootstrap Telemetry
        bootstrap_otel(service_name="agt-dashboard", enable_metrics=True, enable_tracing=True)

    def evaluate_action(self, agent_ctx: dict, action_type: str, params: dict, user_message: str = "") -> GovernanceDecision:
        """Evaluates an action using MAF Kernel directly."""
        self.opa_dispatcher.current_context = agent_ctx
        
        # MAF Execution State Context
        ctx = AdapterExecutionState(
            agent_id=agent_ctx["agent_id"],
            session_id=f"session_{int(time.time())}"
        )
        
        start_ms = time.monotonic() * 1000
        
        if self.maf_kernel:
            if action_type in ("chat", "message"):
                result = self.maf_kernel.evaluate_input(ctx, user_message)
            else:
                result = self.maf_kernel.evaluate_pre_tool_call(
                    ctx, tool_name=action_type, args=params
                )
            allowed = result.allowed
            reason = result.reason or "allowed"
        else:
            # Fallback mock evaluation if Rust/ACS is missing
            # Simulate basic policy logic
            if agent_ctx.get("role") == "admin" or action_type == "chat":
                allowed = True
                reason = "allowed (fallback)"
            else:
                allowed = False
                reason = "denied by fallback policy (Rust/ACS missing)"
            time.sleep(0.05) # simulate latency
            
        elapsed = (time.monotonic() * 1000) - start_ms
        
        # Tamper-evident Audit logging using AGT native
        self.audit_log.write(AuditEntry(
            event_type="policy_evaluation",
            agent_did=agent_ctx["agent_id"],
            action=action_type,
            decision="allow" if allowed else "deny",
            reason=reason
        ))
        
        verdict = GovernanceVerdict.ALLOW if allowed else GovernanceVerdict.DENY
        
        return GovernanceDecision(
            allowed=allowed,
            verdict=verdict,
            reason=reason,
            evaluation_source="acs_manifest" if self.control else "mock_fallback",
            evaluation_ms=elapsed,
            agent_id=agent_ctx["agent_id"],
            action=action_type
        )
