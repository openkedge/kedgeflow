use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use kedgeflow::endpoint::EndpointPolicy;
use std::sync::Arc;

fn headers(host: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_str(host).unwrap());
    headers
}

#[test]
fn configuration_preserves_unambiguous_paths_and_canonical_authorities() {
    for (raw, authority, path) in [
        ("https://LOCALHOST:443/mcp", "localhost", "/mcp"),
        ("https://localhost/mcp", "localhost", "/mcp"),
        ("https://127.0.0.1:8443/mcp", "127.0.0.1:8443", "/mcp"),
        ("https://[0:0:0:0:0:0:0:1]:8443/mcp", "[::1]:8443", "/mcp"),
        ("https://[::1]:443/", "[::1]", "/"),
        (
            "https://xn--bcher-kva.example/a-b_~.v1/",
            "xn--bcher-kva.example",
            "/a-b_~.v1/",
        ),
    ] {
        let policy = EndpointPolicy::new(raw).unwrap();
        assert_eq!(policy.authority(), authority, "{raw}");
        assert_eq!(policy.path(), path, "{raw}");
    }
    for raw in [
        "",
        "http://localhost/mcp",
        "https:localhost/mcp",
        "https:///mcp",
        "https://user:secret@localhost/mcp",
        "https://localhost",
        "https://localhost/mcp?x=1",
        "https://localhost/mcp?",
        "https://localhost/mcp#x",
        "https://localhost/mcp#",
        "https://localhost:/mcp",
        "https://localhost:0/mcp",
        "https://localhost:0443/mcp",
        "https://localhost:65536/mcp",
        "https://localhost:abc/mcp",
        "https://localhost./mcp",
        "https://local_host/mcp",
        "https://bücher.example/mcp",
        "https://a..example/mcp",
        "https://-bad.example/mcp",
        "https://bad-.example/mcp",
        "https://127.1/mcp",
        "https://0x7f.0.0.1/mcp",
        "https://localhost/path^suffix",
        "https://127.000.000.001/mcp",
        "https://[localhost]/mcp",
        "https://::1/mcp",
        "https://[fe80::1%25lo0]/mcp",
        "https://localhost/%6dcp",
        "https://localhost/a%2fb",
        "https://localhost/a/../mcp",
        "https://localhost/./mcp",
        "https://localhost//mcp",
        "https://localhost/mcp\\next",
        "https://localhost/path with space",
        "https://localhost/λ",
    ] {
        assert!(EndpointPolicy::new(raw).is_err(), "{raw}");
    }
}

#[test]
fn rejects_host_origin_and_uri_before_downstream_use() {
    let policy = EndpointPolicy::new("https://localhost:8443/mcp").unwrap();
    for host in [
        "attacker.example:8443",
        "127.0.0.1:8443",
        "localhost:8444",
        "localhost",
        "",
        "localhost.:8443",
        "attacker@localhost:8443",
        "localhost:8443,attacker.example",
        "localhost:",
    ] {
        assert_eq!(
            policy.rejection_status(&headers(host), &Uri::from_static("/mcp")),
            Some(StatusCode::MISDIRECTED_REQUEST),
            "{host}"
        );
    }
    let mut duplicate = headers("localhost:8443");
    duplicate.append("host", HeaderValue::from_static("localhost:8443"));
    assert_eq!(
        policy.rejection_status(&duplicate, &Uri::from_static("/mcp")),
        Some(StatusCode::MISDIRECTED_REQUEST)
    );
    for origin in [
        "https://attacker.example",
        "https://localhost:8443",
        "null",
        "",
    ] {
        let mut h = headers("localhost:8443");
        h.insert("origin", HeaderValue::from_str(origin).unwrap());
        assert_eq!(
            policy.rejection_status(&h, &Uri::from_static("/mcp")),
            Some(StatusCode::FORBIDDEN)
        );
    }
    let mut duplicate = headers("localhost:8443");
    duplicate.append("origin", HeaderValue::from_static(""));
    duplicate.append(
        "origin",
        HeaderValue::from_static("https://attacker.example"),
    );
    assert_eq!(
        policy.rejection_status(&duplicate, &Uri::from_static("/mcp")),
        Some(StatusCode::FORBIDDEN)
    );
    for path in ["/admin", "/mcp/", "/a/../mcp", "/%6dcp", "/mcp%2f"] {
        assert_eq!(
            policy.rejection_status(&headers("localhost:8443"), &path.parse().unwrap()),
            Some(StatusCode::NOT_FOUND),
            "{path}"
        );
    }
    for target in ["/mcp?x=1", "/mcp?", "https://localhost:8443/mcp"] {
        assert_eq!(
            policy.rejection_status(&headers("localhost:8443"), &target.parse().unwrap()),
            Some(StatusCode::BAD_REQUEST),
            "{target}"
        );
    }
    assert_eq!(
        policy.rejection_status(&HeaderMap::new(), &Uri::from_static("/mcp")),
        Some(StatusCode::MISDIRECTED_REQUEST)
    );
}

#[test]
fn valid_native_requests_are_not_rewritten_or_authenticated_by_endpoint_checks() {
    for (endpoint, host) in [
        ("https://localhost:8443/mcp", "LOCALHOST:8443"),
        ("https://localhost/mcp", "localhost:443"),
        ("https://localhost:443/mcp", "localhost"),
        ("https://[::1]:8443/mcp", "[0:0:0:0:0:0:0:1]:8443"),
        ("https://[::1]/mcp", "[::1]:443"),
        ("https://127.0.0.1:8443/mcp", "127.0.0.1:8443"),
    ] {
        let policy = EndpointPolicy::new(endpoint).unwrap();
        let uri = Uri::from_static("/mcp");
        let mut h = headers(host);
        h.insert(
            "forwarded",
            HeaderValue::from_static("host=attacker.example"),
        );
        h.insert(
            "x-forwarded-host",
            HeaderValue::from_static("attacker.example"),
        );
        // Endpoint selection ignores forwarding headers. Authentication must
        // still reject this request because it has no OAuth/DPoP/workload proof.
        policy.validate(&h, &uri).unwrap();
        assert_eq!(h["host"].to_str().unwrap(), host);
        assert_eq!(uri.to_string(), "/mcp");
    }
}

#[test]
fn cloned_endpoint_policy_is_immutable_under_concurrent_requests() {
    let policy = Arc::new(EndpointPolicy::new("https://[::1]:8443/mcp").unwrap());
    let results = (0..32)
        .map(|i| {
            let policy = policy.clone();
            std::thread::spawn(move || {
                let mut h = headers("[::1]:8443");
                if i % 2 == 0 {
                    h.insert(
                        "origin",
                        HeaderValue::from_static("https://attacker.example"),
                    );
                }
                policy.validate(&h, &Uri::from_static("/mcp")).is_ok()
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .into_iter()
            .map(|r| r.join().unwrap())
            .filter(|ok| *ok)
            .count(),
        16
    );
}
