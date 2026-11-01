# Self-hosted Keycloak/SPIRE identity pilot — 30 October 2026

**Passed the bounded identity pilot.** Real Keycloak 26.8.1 issued an Ed25519
DPoP-bound confidential-client access token over verified HTTPS. Real SPIRE
1.15.5 attested Linux UID 1002 and issued its ES256 JWT-SVID and X.509-SVID.
Unregistered UID 1003 could not acquire a JWT-SVID or read the client secret;
the registered workload could not read SPIRE signing keys or reach its private
administrative socket. See the [summary](summary.json).

The native `kf-pilot-identities` checker used the actual SPIRE certificate in a
loopback mTLS connection and verified the original Keycloak token and DPoP proof
with `DualAuthenticator`. The independent broker identity provider verified the
original subject token and JWT-SVID. Their delegation digests matched without
token translation or re-signing. Eight native negatives refused replay, proof-key
substitution, wrong client, wrong subject/actor audience, unregistered workload,
subject withdrawal and implicit original-profile fallback.

[Seventy Rust tests](required-auth.log) across six integration binaries passed
with required real three-member etcd, no runtime skips, plus
[47 Python tests](python.log), [clippy](clippy.log), [Ruff](ruff.log),
[mypy](mypy.log) and the [frozen paper/contract check](whitepaper.log).

The [248 source input hashes](source.json) matched the [pre-run
archive](source.tar.gz) and remained unchanged through execution. The
[baseline revision](revision.txt), [native build](checker-build.log),
[SPIRE image build](spire-build.log), [final image build](workload-build.log),
[tools](tools.json) and exact container metadata retain the build/runtime context.
The Keycloak image and Debian base are digest-pinned; both architecture-specific
SPIRE release archive checksums are pinned in the Dockerfile.

Provider processes ran in Linux ARM64 containers within the local test VM;
the native Rust checker ran on Darwin ARM64. SPIRE-issued credentials were copied
through a private temporary directory for this probe, then deleted. This verifies
cryptographic identity integration, not protected end-to-end workload key custody
across independent hosts. Public output retains the [Keycloak public
JWKS](keycloak-jwks.json) and [SPIRE public bundle](spire-bundle.json), not raw
tokens, client secrets, DPoP seeds or workload private keys.

Both randomly named containers and their internal network were removed after
the run. No host mounts, published ports or privileged mode were used. The
[VM stop record](vm-stop.log) restores the test VM to its original stopped state.
Earlier verification bundles and frozen inputs remain unchanged.

The profile is an explicit Rust pilot opt-in. Existing shipping service loaders
and Node SDK still use the original token profile. No execution grant, broker
mint permit, target credential or SQL mutation was produced. The next increment
is protected shipping-loader/SDK binding and the complete fresh-authority SQL
workflow. Identity administration, key rotation/revocation delivery, durable
head/floor custody, provider database restore, independent deployment/owner
acceptance and AMD64 CI execution remain open. The standalone CI job is prepared;
no remote CI run or enterprise acceptance is claimed.
