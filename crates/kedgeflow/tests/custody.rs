//! POSIX descriptor/mode mechanics only; same UID is not service isolation.
#![cfg(unix)]
use kedgeflow::postgres_custody::{Material, Root};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn fixture() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap().join("protected");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    (dir, root)
}
fn file(root: &Path, name: &str, mode: u32, value: &[u8]) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, value).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}
#[test]
fn protected_public_and_secret_material_is_bounded_and_distinguished() {
    let (_dir, root) = fixture();
    let opened = Root::open(&root).unwrap();
    let public = file(&root, "public", 0o644, b"public");
    let secret = file(&root, "secret", 0o600, b"secret");
    assert_eq!(
        opened.read(&public, Material::Public, 6).unwrap(),
        b"public"
    );
    assert!(opened.read(&public, Material::Secret, 6).is_err());
    assert_eq!(
        opened.read(&secret, Material::Secret, 6).unwrap(),
        b"secret"
    );
    assert!(opened.read(&secret, Material::Secret, 5).is_err());
    assert!(opened.read(&secret, Material::Secret, 0).is_err());
    assert!(
        opened
            .read(&secret, Material::Secret, (1 << 20) + 1)
            .is_err()
    );
    let huge = file(&root, "huge", 0o600, &vec![0; 65537]);
    assert!(opened.read(&huge, Material::Secret, 65536).is_err());
}
#[test]
fn protected_loader_refuses_unsafe_modes_and_hard_links() {
    let (_dir, root) = fixture();
    let opened = Root::open(&root).unwrap();
    for mode in [0o666, 0o664, 0o640, 0o604, 0o700, 0o4700, 0o2700] {
        let path = file(&root, "material", mode, b"secret");
        assert!(
            opened.read(&path, Material::Secret, 64).is_err(),
            "mode {mode:o}"
        );
    }
    let path = file(&root, "material", 0o600, b"secret");
    fs::hard_link(&path, root.join("alias")).unwrap();
    assert!(opened.read(&path, Material::Public, 64).is_err());
    assert!(
        opened
            .read(&root.join("alias"), Material::Secret, 64)
            .is_err()
    );
}
#[test]
fn protected_loader_refuses_symlinks_and_path_escape() {
    let (_dir, root) = fixture();
    let opened = Root::open(&root).unwrap();
    let secret = file(&root, "secret", 0o600, b"secret");
    symlink(&secret, root.join("alias")).unwrap();
    assert!(
        opened
            .read(&root.join("alias"), Material::Secret, 64)
            .is_err()
    );
    fs::create_dir(root.join("sub")).unwrap();
    file(&root.join("sub"), "secret", 0o600, b"nested");
    symlink(root.join("sub"), root.join("linked-sub")).unwrap();
    assert!(
        opened
            .read(&root.join("linked-sub/secret"), Material::Secret, 64)
            .is_err()
    );
    let root_link = root.with_extension("alias");
    symlink(&root, &root_link).unwrap();
    assert!(Root::open(&root_link).is_err());
    assert!(
        opened
            .read(&root.join("sub/../secret"), Material::Secret, 64)
            .is_err()
    );
    assert!(
        opened
            .read(Path::new("secret"), Material::Secret, 64)
            .is_err()
    );
    assert!(
        opened
            .read(&root.with_extension("outside"), Material::Secret, 64)
            .is_err()
    );
    assert!(Root::open(Path::new("/")).is_err());
}
#[test]
fn widened_directory_permissions_and_fifos_fail_closed_without_blocking() {
    let (_dir, root) = fixture();
    let opened = Root::open(&root).unwrap();
    let secret = file(&root, "secret", 0o600, b"secret");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(opened.read(&secret, Material::Secret, 64).is_err());
    assert!(Root::open(&root).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let fifo = root.join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg("-m")
            .arg("600")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let time = Instant::now();
    assert!(opened.read(&fifo, Material::Secret, 64).is_err());
    assert!(time.elapsed() < Duration::from_secs(1));
}
#[test]
fn retained_root_descriptor_does_not_follow_replaced_root_path() {
    let (_dir, root) = fixture();
    file(&root, "secret", 0o600, b"original");
    let opened = Root::open(&root).unwrap();
    fs::rename(&root, root.with_extension("old")).unwrap();
    fs::create_dir(&root).unwrap();
    file(&root, "secret", 0o600, b"replacement");
    assert_eq!(
        opened
            .read(&root.join("secret"), Material::Secret, 64)
            .unwrap(),
        b"original"
    );
    assert_eq!(
        Root::open(&root)
            .unwrap()
            .read(&root.join("secret"), Material::Secret, 64)
            .unwrap(),
        b"replacement"
    );
}
