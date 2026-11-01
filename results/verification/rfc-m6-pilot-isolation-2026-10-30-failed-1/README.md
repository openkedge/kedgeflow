# Failed Linux account fixture — missing tool path

The first ARM64 container run exited before creating accounts because the
fixture's restricted PATH omitted `/usr/sbin`, where `useradd` is installed.
[Failure log](fixture.log), [summary](summary.json) and [source archive](source.tar.gz)
preserve the observation. The container was removed. This run provides no
positive qualification; the [later passing
record](../rfc-m6-pilot-isolation-2026-10-30/README.md) uses corrected source.
