"""
AGT Governance Dashboard — FastAPI Backend
"""
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Any
from pathlib import Path

from .models import (
    Unit, UnitCreate, Role, RoleCreate, Agent, AgentCreate,
    ChatRequest, ChatResponse, ChatMessage, AgentDID, DashboardStats
)
from .agt_integration import GovernanceRuntime

app = FastAPI(title="AGT Governance Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory database for demo
DB = {
    "units": {},
    "roles": {},
    "agents": {}
}

# Initialize Governance Runtime
MANIFEST_PATH = str(Path(__file__).parent.parent / "policies" / "manifest.yaml")
OPA_URL = "http://localhost:8181"
governance = GovernanceRuntime(manifest_path=MANIFEST_PATH, opa_url=OPA_URL)

@app.get("/")
def health_check():
    return {"status": "healthy", "service": "agt-dashboard-backend"}

# ── Units ──

@app.post("/api/units", response_model=Unit)
def create_unit(unit: UnitCreate):
    new_unit = Unit(**unit.model_dump())
    DB["units"][new_unit.id] = new_unit
    return new_unit

@app.get("/api/units", response_model=list[Unit])
def list_units():
    return list(DB["units"].values())

# ── Roles ──

@app.post("/api/units/{unit_id}/roles", response_model=Role)
def create_role(unit_id: str, role: RoleCreate):
    if unit_id not in DB["units"]:
        raise HTTPException(status_code=404, detail="Unit not found")
    new_role = Role(**role.model_dump(), unit_id=unit_id)
    DB["roles"][new_role.id] = new_role
    return new_role

@app.get("/api/roles", response_model=list[Role])
def list_roles():
    return list(DB["roles"].values())

# ── Agents ──

@app.post("/api/agents", response_model=Agent)
def create_agent(agent: AgentCreate):
    unit = DB["units"].get(agent.unit_id)
    role = DB["roles"].get(agent.role_id)
    if not unit or not role:
        raise HTTPException(status_code=404, detail="Unit or Role not found")
    
    did = AgentDID.generate(name=agent.name, org=unit.name)
    new_agent = Agent(
        **agent.model_dump(),
        unit_name=unit.name,
        role_name=role.name,
        did=str(did),
        capabilities=role.allowed_tools
    )
    DB["agents"][new_agent.id] = new_agent
    return new_agent

@app.get("/api/agents", response_model=list[Agent])
def list_agents():
    return list(DB["agents"].values())

# ── Chat / Agent Execution ──

@app.post("/api/chat", response_model=ChatResponse)
def chat_with_agent(req: ChatRequest):
    agent = DB["agents"].get(req.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    unit = DB["units"][agent.unit_id]
    role = DB["roles"][agent.role_id]
    
    # Build Context
    agent_ctx = {
        "agent_id": agent.did,
        "unit": unit.name,
        "role": role.name,
        "can_access_pii": role.can_access_pii,
        "model": req.model,
        "mcp_server": req.mcp_server,
    }
    
    # Check Governance
    if req.tool_name:
        decision = governance.evaluate_action(agent_ctx, req.tool_name, req.tool_args)
        action_msg = f"Executed tool {req.tool_name}" if decision.allowed else f"Blocked tool {req.tool_name}: {decision.reason}"
    else:
        decision = governance.evaluate_action(agent_ctx, "chat", {}, user_message=req.message)
        action_msg = f"Processed message" if decision.allowed else f"Blocked message: {decision.reason}"
        
    return ChatResponse(
        message=ChatMessage(role="assistant", content=action_msg, governance=decision),
        governance_decisions=[decision],
        audit_entries=[]
    )

# ── Dashboard Stats ──

@app.get("/api/stats", response_model=DashboardStats)
def get_stats():
    return DashboardStats(
        total_units=len(DB["units"]),
        total_roles=len(DB["roles"]),
        total_agents=len(DB["agents"]),
    )

if __name__ == "__main__":
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
