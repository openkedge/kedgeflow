#!/usr/bin/env python3
"""Conflicting Agents Demo - Multi-Agent Control Plane Conflict Resolution.

Demonstrates:
  1. Two independent agents: deployment-agent and ops-agent.
  2. deployment-agent proposes: deploy workload-Y -> instance/i-17.
     Controller evaluates: Valid -> GRANT. Controller records pending transition in global state.
  3. ops-agent proposes: terminate instance/i-17 (with health==failed evidence).
     Locally, ops-agent's action seems reasonable based on its isolated perception.
     Globally, controller detects an active conflict on instance/i-17.
  4. Controller DENIES termination proposal with clear conflict reason.
  5. Proves that local agent cognition != global control-plane view.
"""

from kedgeflow.demos.conflict import run_conflict_demo

if __name__ == "__main__":
    run_conflict_demo()
