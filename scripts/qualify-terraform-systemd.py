#!/usr/bin/env python3
"""Run real Terraform qualification on an explicitly disposable systemd VM."""

import argparse
import hashlib
import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path


def run(args, **kw):
    return subprocess.run(list(map(str, args)), check=True, text=True, timeout=120, **kw)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ephemeral-host", action="store_true", required=True)
    p.add_argument("--base", type=Path, required=True)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--bin-dir", type=Path, required=True)
    p.add_argument("--tools", type=Path, required=True)
    p.add_argument("--kubeconfig", type=Path, required=True)
    p.add_argument("--context", required=True)
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--etcd", type=Path, required=True)
    p.add_argument("--work-disk", type=Path, required=True)
    a = p.parse_args()
    assert (
        os.geteuid() == 0
        and Path("/proc/1/comm").read_text().strip() == "systemd"
        and a.base.parent == Path("/run")
        and a.base.name.startswith("kf-tflinux-")
    )
    run([a.node_dir / "node", "--version"])
    a.base.mkdir(mode=0o755, exist_ok=False)
    suffix = a.base.name[-8:]
    gw = "kftg" + suffix
    agent = "kfta" + suffix
    sudoers = Path("/etc/sudoers.d") / ("kf-tfi-" + suffix)
    users = []
    out = a.base / "output"
    out.mkdir()
    work = a.base / "work"
    work.mkdir(mode=0o700)
    try:
        for user in (gw, agent):
            run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", user])
            users.append(user)
        identity = pwd.getpwnam(gw)
        a.work_disk.mkdir(mode=0o700, exist_ok=False)
        run(["mount", "--bind", a.work_disk, work])
        os.chown(work, identity.pw_uid, identity.pw_gid)
        os.chown(out, identity.pw_uid, identity.pw_gid)
        state = {
            "base": str(a.base),
            "gateway_user": gw,
            "agent_user": agent,
            "source": str(a.source),
            "bin_dir": str(a.bin_dir),
            "node_dir": str(a.node_dir),
            "audit_node": "kf8-tfpa20261109-control-plane",
        }
        statepath = a.base / "state.json"
        statepath.write_text(json.dumps(state))
        statepath.chmod(0o600)
        helper = a.source / "scripts/terraform-systemd-fixture.py"
        sudoers.write_text(
            gw
            + " ALL=(root) NOPASSWD: /usr/bin/python3 "
            + str(helper)
            + " --state "
            + str(statepath)
            + " *\n"
        )
        sudoers.chmod(0o440)
        run(["visudo", "-cf", sudoers])
        audit = a.base / "audit-docker"
        audit.write_text(
            "#!/bin/sh\nexec sudo -n /usr/bin/python3 "
            + str(helper)
            + " --state "
            + str(statepath)
            + " --action audit --material "
            + str(work)
            + "\n"
        )
        audit.chmod(0o755)
        kcfg = a.base / "kubeconfig"
        shutil.copyfile(a.kubeconfig, kcfg)
        os.chown(kcfg, identity.pw_uid, identity.pw_gid)
        kcfg.chmod(0o600)
        common = [
            "python3",
            str(a.source / "scripts/test-terraform-plan.py"),
            "--terraform",
            str(a.tools / "terraform"),
            "--provider",
            str(a.tools / "kubernetes"),
            "--kubectl",
            "/usr/local/bin/kubectl",
            "--kubeconfig",
            str(kcfg),
            "--context",
            a.context,
            "--inspector",
            str(a.bin_dir / "kf-terraform-plan"),
        ]
        cases = [
            ("normal", "official_sdk_shipping_gateway_and_broker_apply_then_cold_query", None),
            (
                "cgroup-drop",
                "systemd::service_cgroup_stops_escaped_child_and_original_query",
                "systemd-kill-drop",
            ),
            (
                "cgroup-late",
                "systemd::service_cgroup_cleanup_still_retains_late_effect",
                "systemd-kill-late",
            ),
            ("pair-partial", "official_sdk_pair_partial_keeps_unknown", "pair"),
        ]
        driver = a.base / "driver.py"
        driver.write_text(
            "import subprocess,json\nfrom pathlib import Path\n"
            + f"cases={cases!r}\ncommon={common!r}\nout=Path({str(out)!r})\n"
            + f"source=Path({str(a.source)!r})\nbins=Path({str(a.bin_dir)!r})\n"
            + """
for name,test,mode in cases:
 cmd=[*common,'--output',str(out/name)]
 audit=['--docker',str(out.parent/'audit-docker'),
        '--audit-node','kf8-tfpa20261109-control-plane']
 if mode and mode!='pair':cmd+=['--active-child',mode,*audit]
 if name in ('normal','cgroup-late'):cmd+=['--expect-effect']
 if mode=='pair':
  cmd+=['--pair-inspector',str(bins/'kf-terraform-pair-plan'),
        '--pair-execution','partial',*audit]
 cmd+=['--execution-command',str(bins/'governance-test'),
       'terraform_apply::gateway::'+test,'--exact','--nocapture','--test-threads=1']
 with (out/(name+'.log')).open('w') as f:
  r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300,cwd=source)
 print(json.dumps({'case':name,'exit':r.returncode}),flush=True)
 if r.returncode:raise SystemExit(r.returncode)
"""
        )
        driver.chmod(0o644)
        env = {
            **os.environ,
            "PATH": str(a.node_dir)
            + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TMPDIR": str(work),
            "ETCD_BINARY": str(a.etcd),
            "KF_TERRAFORM_SYSTEMD_STATE": str(statepath),
            "KF_SELFHOSTED_SOURCE_ROOT": str(a.source),
            "KF_TERRAFORM_SYSTEMD_HELPER": str(helper),
        }
        with (out / "live.log").open("w") as f:
            result = subprocess.run(
                [
                    "runuser",
                    "-u",
                    gw,
                    "--",
                    "env",
                    *[
                        k + "=" + v
                        for k, v in env.items()
                        if k
                        in (
                            "PATH",
                            "TMPDIR",
                            "ETCD_BINARY",
                            "KF_TERRAFORM_SYSTEMD_STATE",
                            "KF_TERRAFORM_SYSTEMD_HELPER",
                            "KF_SELFHOSTED_SOURCE_ROOT",
                        )
                    ],
                    "bash",
                    str(a.source / "scripts/start-etcd.sh"),
                    "--",
                    "python3",
                    str(driver),
                ],
                text=True,
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=1500,
            )
        if result.returncode:
            raise RuntimeError(
                "real Linux service qualification failed; inspect live and case logs"
            )
        (out / "host.json").write_text(
            json.dumps(
                {
                    "systemd": subprocess.check_output(
                        ["systemctl", "--version"], text=True
                    ).splitlines()[0],
                    "kernel": os.uname().release,
                    "uid": identity.pw_uid,
                    "agent_uid": pwd.getpwnam(agent).pw_uid,
                    "runtime_sha256": {
                        n: hashlib.sha256((a.bin_dir / n).read_bytes()).hexdigest()
                        for n in ["kf-proxy", "kf-broker"]
                    },
                    "same_host_administered_fixture": True,
                },
                indent=2,
            )
            + "\n"
        )
    finally:
        units = []
        for record in a.base.glob("case-*.json"):
            data = json.loads(record.read_text())
            unit = data["unit"]
            assert unit.startswith("kf-tfi-") and unit.endswith(".service")
            run(["systemctl", "stop", unit])
            subprocess.run(["systemctl", "reset-failed", unit], capture_output=True, timeout=30)
            path = Path("/etc/systemd/system") / unit
            if path.exists():
                path.unlink()
            units.append(unit)
        run(["systemctl", "daemon-reload"])
        if sudoers.exists():
            sudoers.unlink()
        for user in reversed(users):
            identity = pwd.getpwnam(user)
            subprocess.run(
                ["pkill", "-KILL", "-u", str(identity.pw_uid)], capture_output=True, timeout=20
            )
            run(["userdel", user])
        (out / "cleanup.json").write_text(
            json.dumps(
                {
                    "units_removed": units,
                    "users_removed": users,
                    "sudo_rule_removed": not sudoers.exists(),
                    "service_processes_stopped": True,
                },
                indent=2,
            )
            + "\n"
        )
    print(json.dumps({"status": "PASS", "output": str(out)}))


if __name__ == "__main__":
    main()
