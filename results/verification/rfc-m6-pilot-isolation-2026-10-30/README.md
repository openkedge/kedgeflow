# Protected pilot Linux account fixture — 30 October 2026

**Passed the bounded Linux ARM64 fixture:** ten qualification groups and five
live TLS/HTTP probes against the shipping PostgreSQL target. See
[summary](summary.json), [probe report](report.json), [tools](tools.txt),
[source hashes](source.json) and [exact source archive](source.tar.gz).

The four database/target/agent/recovery kernel UIDs were 1000/1001/1002/1003.
Recovery queried a missing original attempt through the protected target and
actual SQL, receiving `404 unknown_outcome`. CA-issued agent requests carrying
the correct query bearer refused query and dispatch with `401 invalid_workload`;
the enrolled recovery identity with a wrong bearer received
`401 invalid_credential`; no client certificate failed TLS.

The existing socket, peer-map, SQL role and file/shell/Python bypass probes also
passed. Agent access to recovery and CA private keys refused; recovery could not
connect directly as the SQL reader. The fixture retained zero SQL attempts.
Post-run `/etc/passwd` and `/etc/group` observations found zero generated fixture
entries, and the exact fixture container was removed.

The [image](image.json) ran with no host mounts, published ports, external
networking or privileged mode, with a 1 GiB memory and 256-process limit. The
[container record](container.json) retains the actual settings and zero exit
status. The 243 build inputs matched before and after execution and match both
the image manifest and archived file bodies. [Build log](build.log),
[initial compilation log](compile.log) and [package versions](packages.txt)
retain the build provenance. The final build reused the unchanged compiled Rust
layer; fixture corrections were copied afterward.

The final local regressions passed [45 Python tests](python.log),
[Ruff](ruff.log), [mypy](mypy.log) and the [frozen paper/contract
check](whitepaper.log). Earlier tracked verification and frozen inputs are
unchanged. The [VM stop log](vm-stop.log) records restoration of the test VM to
its original stopped state after removing the fixture and failed build containers.

Two failed runs remain separate: [missing administrative-tool
PATH](../rfc-m6-pilot-isolation-2026-10-30-failed-1/README.md) and
[unreadable root-owned ancestor](../rfc-m6-pilot-isolation-2026-10-30-failed-2/README.md).
The final fixture includes `/usr/sbin` in its controlled path and uses a readable
root-owned ancestor with private per-role secret directories. Neither correction
weakens the shipping target's checks. Failed runs do not qualify this revision.

This is a same-implementation, same-kernel disposable container observation.
Linux AMD64 CI execution, approved enterprise providers, independently
administered ACLs/launchers/mounts/custody/rotation, writer/storage/physical
restore/retention/SLO and owner acceptance remain open. No enterprise gate or
M8 frozen result is changed by this pass. The new independent CI job is prepared
in the working tree; no remote CI execution is claimed.
