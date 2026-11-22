//! RUSTSEC-2026-0592: attacker-controlled nested blob origins must not abort
//! a normal worker thread through unbounded recursion.

use std::thread;
use url::{Origin, Url};

#[test]
fn deeply_nested_blob_origin_is_opaque_on_a_normal_worker_stack() {
    thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            let nested = format!("{}https://example.invalid/", "blob:".repeat(10_000));
            let parsed = Url::parse(&nested).expect("valid nested blob URL");
            assert!(matches!(parsed.origin(), Origin::Opaque(_)));
        })
        .expect("spawn worker")
        .join()
        .expect("worker computes an origin without overflowing its stack");
}
