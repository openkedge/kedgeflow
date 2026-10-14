#![cfg(unix)]
use kedgeflow::postgres_socket;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};
fn listener() -> (tempfile::TempDir, PathBuf, tokio::net::UnixListener) {
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let listener = tokio::net::UnixListener::bind(root.join(".s.PGSQL.5432")).unwrap();
    fs::set_permissions(
        root.join(".s.PGSQL.5432"),
        fs::Permissions::from_mode(0o770),
    )
    .unwrap();
    (tmp, root, listener)
}
#[tokio::test]
async fn connected_kernel_peer_is_pinned_before_protocol_bytes() {
    let (_tmp, root, listener) = listener();
    let uid = rustix::process::geteuid().as_raw();
    let stream = postgres_socket::connect(&root, 5432, uid).await.unwrap();
    let (mut accepted, _) = listener.accept().await.unwrap();
    use tokio::io::AsyncReadExt;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), accepted.read_u8())
            .await
            .is_err()
    );
    drop(stream);
    assert!(
        postgres_socket::connect(&root, 5432, uid + 1)
            .await
            .is_err()
    );
    assert!(postgres_socket::connect(&root, 5432, 0).await.is_err());
}
#[tokio::test]
async fn unsafe_socket_paths_and_modes_refuse() {
    let (_tmp, root, _listener) = listener();
    let uid = rustix::process::geteuid().as_raw();
    let socket = root.join(".s.PGSQL.5432");
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(postgres_socket::connect(&root, 5432, uid).await.is_err());
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o770)).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(postgres_socket::connect(&root, 5432, uid).await.is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(&socket, root.join("original")).unwrap();
    symlink(root.join("original"), &socket).unwrap();
    assert!(postgres_socket::connect(&root, 5432, uid).await.is_err());
    assert!(
        postgres_socket::connect(&root.join("../anything"), 5432, uid)
            .await
            .is_err()
    );
    let alias = root.with_extension("alias");
    symlink(&root, &alias).unwrap();
    assert!(postgres_socket::connect(&alias, 5432, uid).await.is_err());
    fs::remove_file(alias).unwrap();
}
