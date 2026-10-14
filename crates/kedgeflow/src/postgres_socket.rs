//! Opt-in kernel peer pinning before any PostgreSQL protocol bytes are sent.
use crate::error::{Error, Result};
use std::path::Path;

fn refuse() -> Error {
    Error::Refused("protected PostgreSQL peer transport rejected".into())
}

#[cfg(unix)]
pub async fn connect(directory: &Path, port: u16, uid: u32) -> Result<tokio::net::UnixStream> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::path::{Component, PathBuf};
    if uid == 0 || port == 0 || !directory.is_absolute() {
        return Err(refuse());
    }
    let caller = rustix::process::geteuid().as_raw();
    let mut path = PathBuf::from("/");
    let components: Vec<_> = directory.components().collect();
    if components.len() < 2 {
        return Err(refuse());
    }
    for (index, part) in components.iter().enumerate() {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => path.push(name),
            _ => return Err(refuse()),
        }
        let meta = std::fs::symlink_metadata(&path).map_err(|_| refuse())?;
        let sticky_ancestor =
            index + 1 < components.len() && meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        if !meta.is_dir()
            || ![0, caller, uid].contains(&meta.uid())
            || meta.mode() & 0o6000 != 0
            || (meta.mode() & 0o022 != 0 && !sticky_ancestor)
        {
            return Err(refuse());
        }
    }
    let parent = std::fs::symlink_metadata(directory).map_err(|_| refuse())?;
    if parent.uid() != uid {
        return Err(refuse());
    }
    let socket = directory.join(format!(".s.PGSQL.{port}"));
    let before = std::fs::symlink_metadata(&socket).map_err(|_| refuse())?;
    let valid = |meta: &std::fs::Metadata| {
        meta.file_type().is_socket() && meta.uid() == uid && meta.mode() & 0o7007 == 0
    };
    if !valid(&before) {
        return Err(refuse());
    }
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::UnixStream::connect(&socket),
    )
    .await
    .map_err(|_| refuse())?
    .map_err(|_| refuse())?;
    if stream.peer_cred().map_err(|_| refuse())?.uid() != uid {
        return Err(refuse());
    }
    let after = std::fs::symlink_metadata(&socket).map_err(|_| refuse())?;
    let current_parent = std::fs::symlink_metadata(directory).map_err(|_| refuse())?;
    if !valid(&after)
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || parent.dev() != current_parent.dev()
        || parent.ino() != current_parent.ino()
        || current_parent.uid() != uid
        || current_parent.mode() & 0o6022 != 0
    {
        return Err(refuse());
    }
    Ok(stream)
}
