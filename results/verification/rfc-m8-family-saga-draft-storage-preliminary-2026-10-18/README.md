# Retained preliminary run across host disk exhaustion — 18 October 2026

This required full conformance attempt FAILED and is not accepted qualification.
It used the identical 527-file frozen source retained in source.zip and
source-sha256.json, baseline fc54d0e. No source file or production guard changed.

The earlier sleep-affected real-row-lock case passed in this attempt. All new
proposal/stop tests also passed. Later etcd transport failures cascaded into 21
failed governance cases; independent witness startup explicitly reported
failed to create WAL: no space left on device. These actual failures remain in
the full required-runtime.log and summary. The host had 1.3 GiB available after
runner cleanup, and the rebuildable task Rust output directory occupied 5.9 GiB.

Before another unchanged-source attempt, only this task's rebuildable Cargo
outputs are cleaned and dev/test debug information plus incremental caches are
disabled for the new build. User files and committed evidence are retained.
This is a build/environment adjustment, not a relaxed production limit. The
subsequent required full suite must pass independently.
