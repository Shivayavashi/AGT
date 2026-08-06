"""
MAF Agent Example

Since the `agent_framework` library is an external dependency (not present in this environment), 
this file demonstrates how a MAF Agent is typically created and governed by the AGT Toolkit.

In reality, the `MAFKernel` (used in `agt_integration.py`) is injected into the MAF Agent
as a middleware layer.
"""
from typing import Any

class MockMAFAgent:
    """
    A mock representation of a Microsoft Agent Framework (MAF) Agent.
    """
    def __init__(self, agent_id: str, name: str, maf_kernel: Any):
        self.agent_id = agent_id
        self.name = name
        # The MAFKernel (created in agt_integration.py) acts as the governance 
        # middleware intercepting the inputs and tool calls of the agent.
        self.maf_kernel = maf_kernel
        
    def process_message(self, session_id: str, message: str) -> dict:
        """Simulates receiving a user message."""
        # 1. The MAF adapter evaluates the input BEFORE the agent sees it
        ctx = type('MockContext', (), {'agent_id': self.agent_id, 'session_id': session_id})()
        input_decision = self.maf_kernel.evaluate_input(ctx, message)
        
        if not input_decision.allowed:
            return {"error": f"Message blocked by AGT: {input_decision.reason}"}
            
        return {"response": f"Agent {self.name} received message safely."}

    def execute_tool(self, session_id: str, tool_name: str, args: dict) -> dict:
        """Simulates the agent attempting to call a tool."""
        # 2. The MAF adapter evaluates the tool call BEFORE execution
        ctx = type('MockContext', (), {'agent_id': self.agent_id, 'session_id': session_id})()
        tool_decision = self.maf_kernel.evaluate_pre_tool_call(ctx, tool_name, args)
        
        if not tool_decision.allowed:
            return {"error": f"Tool blocked by AGT: {tool_decision.reason}"}
            
        return {"result": f"Executed {tool_name} successfully."}
