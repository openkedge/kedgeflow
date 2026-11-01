# Failed Linux account fixture — unreadable ancestor

With administrative tools available, the fixture reached shipping protected-file
preflight, which correctly refused its root-owned mode-0711 ancestor. The loader
opens every ancestor directory read-only; the target UID could traverse that
directory but could not open it read-only. [Failure log](fixture.log),
[summary](summary.json) and [source archive](source.tar.gz) preserve this revision.
The container was removed. The [later passing
record](../rfc-m6-pilot-isolation-2026-10-30/README.md) uses a root-owned readable
ancestor while retaining mode-0700 per-role secret directories. No shipping
enforcement check changed.
