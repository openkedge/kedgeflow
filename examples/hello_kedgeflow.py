#!/usr/bin/env python3
"""Hello KedgeFlow - Working End-to-End Demo.

Demonstrates:
  1. Agent proposes a consequential transition (compute.terminate).
  2. Controller evaluates policy, evidence, and state, issuing bounded authority with a live guard.
  3. Enforcer validates authority and live guard (production.capacity > 3) when capacity is 4.
  4. Tool executes and generates an immutable execution receipt.
  5. Capacity drops to 3 (e.g. concurrent events). A new or pending execution attempts to proceed.
  6. Enforcer intercepts and blocks execution because live guard (3 > 3) fails!
"""

from kedgeflow.demos.hello import run_demo

if __name__ == "__main__":
    run_demo()
