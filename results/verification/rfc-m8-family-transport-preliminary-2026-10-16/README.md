# Preliminary family transport fixture qualification — 16 October 2026

This unchanged-source full run passed all 190 governance cases, including all ten
family cases, and all earlier runtime binaries. The final transport population
failed because its synthetic etcd endpoint returned one response to the new
three-range marker observation. Production correctly refused the incomplete
response. This run is not final qualification. source.zip retains its exact
515-file tested source; summary.json and source-archive.json pin source, tools,
commands and original logs. The subsequent repair changes only the synthetic
transport response, preserving the authorization-header assertion and runtime
fail-closed behavior. Earlier committed evidence is unchanged.
