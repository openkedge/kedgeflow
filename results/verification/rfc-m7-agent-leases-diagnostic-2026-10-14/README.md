# M7d2 diagnostic vector run — 14 October 2026

This run passed the quality, Python, Node legacy and frozen contract checks, then
failed the new lease vectors before native runtime qualification. The vector
copied a frozen paper proposal with a saga workflow and commit-bound completion;
the new single-leaf client correctly refused that unsupported profile.

The test copy now explicitly uses null workflow and dispatch-bound completion,
matching the native leaf fixture; frozen paper records remain unchanged. Original
summary/log bytes are retained. This failed diagnostic is not qualification for
the final source. See the [final record](../rfc-m7-agent-leases-2026-10-14/README.md).
