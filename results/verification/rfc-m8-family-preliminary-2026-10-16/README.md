# Preliminary family authority conformance — 16 October 2026

This frozen development run failed two existing inverse SQL cases. All nine new
family tests passed; it is not final qualification. The unchanged tested source
is retained in source.zip and pinned by summary.json. Earlier committed evidence
is untouched. A subsequent repair also binds the exact namespace into family
registration/commands, so this preliminary source must not be confused with the
final implementation. See the later family authority verification record.

Failures: the shipping target/native adapter returned unknown with an unavailable
inverse reply; target-kill-after-COMMIT setup refused proposal binding before fresh
issuance. The host slept during this run (see power-observations.json), consistent
with real-clock expiry while processes were paused. No production validity window
was extended. Original logs and command/source/tool hashes remain unchanged.
