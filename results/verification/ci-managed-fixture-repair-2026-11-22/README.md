# Managed provider CI fixture repair

The full security-patch run [45068628813](https://github.com/openkedge/kedgeflow/actions/runs/45068628813)
passed all eleven required jobs. Later run
[45069757949](https://github.com/openkedge/kedgeflow/actions/runs/45069757949)
failed its managed provider/systemd workflow before starting the Rust test.
Read-only artifact inspection returned only fixed categories and source frames:
`PermissionError` at the copied PostgreSQL `--version` executable in
`qualify-systemd-authority.py`. No raw provider logs or credentials were exported.

That fixture placed PostgreSQL and the shipping runtime under `/run`. The repair
places executable copies in an exclusively owned temporary `/opt` directory,
checks that it is executable, and keeps private runtime state under `/run`.
The fixture also sets its intended public traversal and SQL socket modes
explicitly, independent of a protected `0077` umask. Positive peer logins now
check both intended target SQL roles before the provider workflow starts.
Temporary service identities use system accounts without unnecessary subordinate
UID ranges; this avoids an unrelated seven-account allocation limit observed in
the disposable local VM.

The local ARM64 regression reproduced the old PostgreSQL execution error with
a private noexec runtime mount. The repaired harness, under umask `0077`, passed
real database creation, intended executor/reader peer logins and the negative
role checks, then reached an explicitly failing shipping-test stub. The provider
workflow was **not executed** in this staging regression. Its temporary accounts,
processes and mount were removed. The old-path comparison used a system-account
creation shim solely to avoid the local subordinate-UID quota. The standalone
native SQL isolation fixture also passed its ten checks under the strict umask.
See `local-regression.json` for the bounded result and source hashes.

Failures now propagate only a closed phase, error class and mount flags through
the Python runner layers into CI annotations. Unknown output cannot become a
diagnostic payload. The artifact download token is sent only to GitHub's API;
the redirected storage request has no authorization header.

The temporary artifact reproduction and failure-inspection workflows are now
manual diagnostics with explicit run/source/digest inputs. Ordinary pushes do
not depend on retained artifacts that will expire. The required CI workflow
still runs all existing qualification gates, including the full real-provider
systemd workflow. These local observations do not replace its required successful
run, independent reproduction or enterprise acceptance.
