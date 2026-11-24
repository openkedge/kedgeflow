#!/usr/bin/env python3
"""Reject empty JUnit reports and any skipped, failed or errored test case."""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def verify(path: Path) -> int:
    cases = list(ET.parse(path).getroot().iter("testcase"))
    if not cases or any(
        case.find(name) is not None for case in cases for name in ("skipped", "failure", "error")
    ):
        raise ValueError("required test population is empty, skipped or failed")
    return len(cases)


if __name__ == "__main__":
    print(f"Required JUnit cases passed without skips: {verify(Path(sys.argv[1]))}")
