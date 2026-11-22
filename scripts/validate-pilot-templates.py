#!/usr/bin/env python3
"""Schema-check all Cura CloudFormation variants without accessing AWS."""

import json
import runpy
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    templates = {}
    for name in (
        "bootstrap",
        "image-builder",
        "custody",
        "infrastructure",
        "enrollment-bridge",
        "run-window",
    ):
        render = runpy.run_path(str(ROOT / f"scripts/pilot-{name}.py"))["template"]
        templates[name] = render()
        if name == "infrastructure":
            templates["infrastructure-existing-budget"] = render(existing_budget=True)
    checked_in = json.loads((ROOT / "deploy/pilot/cura/infrastructure-v1.json").read_text())
    if checked_in != templates["infrastructure"]:
        raise RuntimeError("checked-in infrastructure differs from its renderer")
    with tempfile.TemporaryDirectory(prefix="kedgeflow-cfn-") as temporary:
        files = []
        for name, template in templates.items():
            path = Path(temporary) / (name + ".json")
            path.write_text(json.dumps(template))
            files.append(str(path))
        subprocess.run(["cfn-lint", *files], check=True)
    print(f"Validated all {len(templates)} Cura CloudFormation variants; no AWS calls")


if __name__ == "__main__":
    main()
