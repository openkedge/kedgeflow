# Retained preliminary run across host suspension — 18 October 2026

This required full conformance attempt FAILED and is not accepted qualification.
Its exact frozen 527-file source is retained in source.zip and source-sha256.json;
source files stayed unchanged throughout the run. The baseline is fc54d0e.

During the real-row-lock inverse process-kill fixture the host entered clamshell
sleep at 00:41:17 PDT and woke at 00:43:59 (162 seconds), as retained in
host-suspension.json. Admission subsequently refused an expired original proposal:
proposal does not bind identity/current leaf descriptor. No production lifetime,
unknown-consumption or replay guard was changed. Later cases continued normally.
The complete runner logs and summary retain the actual result. Subsequent
qualification must independently pass the required unchanged-source suite.
