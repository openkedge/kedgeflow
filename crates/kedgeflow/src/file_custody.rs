//! Descriptor-relative, bounded reads of operator-owned Unix material.
//! This does not isolate processes sharing the same UID or protect against root.
use crate::error::{Error, Result};
use std::path::Path;

/// Largest configuration/key input: the 2 MiB recovery/delivery configuration.
/// Individual readers retain their narrower record/key-specific bounds.
pub const MAX_READ: usize = 2 << 20;

fn refused() -> Error {
    Error::Refused("protected file custody rejected".into())
}
#[derive(Clone, Copy)]
pub enum Material {
    Public,
    Secret,
}
#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::{
        fs::File,
        io::{Read, Write},
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Component, PathBuf},
    };
    pub struct Root {
        directory: File,
        path: PathBuf,
        uid: u32,
    }
    fn components(path: &Path) -> Result<Vec<&std::ffi::OsStr>> {
        if !path.is_absolute() {
            return Err(refused());
        }
        path.components()
            .filter_map(|part| match part {
                Component::RootDir => None,
                Component::Normal(name) => Some(Ok(name)),
                _ => Some(Err(refused())),
            })
            .collect()
    }
    fn directory(file: &File, uid: u32, sticky_ancestor: bool) -> Result<()> {
        let meta = file.metadata().map_err(|_| refused())?;
        let mode = meta.mode();
        let sticky = sticky_ancestor && meta.uid() == 0 && mode & 0o1000 != 0;
        if !meta.is_dir()
            || (meta.uid() != 0 && meta.uid() != uid)
            || mode & 0o6000 != 0
            || (mode & 0o022 != 0 && !sticky)
        {
            return Err(refused());
        }
        Ok(())
    }
    fn regular(meta: &std::fs::Metadata, uid: u32, kind: Material, bound: usize) -> Result<()> {
        let private = matches!(kind, Material::Secret);
        if !meta.is_file()
            || meta.nlink() != 1
            || (meta.uid() != 0 && meta.uid() != uid)
            || meta.mode() & 0o7111 != 0
            || meta.mode() & 0o022 != 0
            || (private && meta.mode() & 0o077 != 0)
            || meta.len() > bound as u64
        {
            return Err(refused());
        }
        Ok(())
    }
    impl Root {
        pub fn open(path: &Path) -> Result<Self> {
            let uid = rustix::process::geteuid().as_raw();
            if uid == 0 {
                return Err(refused());
            }
            let names = components(path)?;
            if names.is_empty() {
                return Err(refused());
            }
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let mut fd: File = open("/", flags, Mode::empty())
                .map_err(|_| refused())?
                .into();
            directory(&fd, uid, true)?;
            for (index, name) in names.iter().enumerate() {
                fd = openat(&fd, *name, flags, Mode::empty())
                    .map_err(|_| refused())?
                    .into();
                directory(&fd, uid, index + 1 < names.len())?;
            }
            Ok(Self {
                directory: fd,
                path: path.into(),
                uid,
            })
        }
        pub fn uid(&self) -> u32 {
            self.uid
        }
        /// Publish a publisher-owned batch for its dedicated administrative
        /// group. This is not a service-secret writer: consumers still reject
        /// group-readable secrets, and this operation never changes ownership.
        pub fn stage_batch(&self, bytes: &[u8]) -> Result<()> {
            let meta = self.directory.metadata().map_err(|_| refused())?;
            if bytes.is_empty()
                || bytes.len() > 512 * 1024
                || meta.uid() != self.uid
                || meta.gid() != rustix::process::getegid().as_raw()
                || meta.mode() & 0o7777 != 0o750
            {
                return Err(refused());
            }
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            match openat(&self.directory, "batch.json", flags, Mode::empty()) {
                Ok(fd) => {
                    let existing: File = fd.into();
                    let m = existing.metadata().map_err(|_| refused())?;
                    if !m.is_file()
                        || m.nlink() != 1
                        || m.uid() != self.uid
                        || m.gid() != meta.gid()
                        || m.mode() & 0o7777 != 0o440
                    {
                        return Err(refused());
                    }
                }
                Err(rustix::io::Errno::NOENT) => {}
                Err(_) => return Err(refused()),
            }
            let name = format!(".batch-{:032x}", rand::random::<u128>());
            let fd = openat(
                &self.directory,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| refused())?;
            let result = (|| {
                let mut file: File = fd.into();
                file.write_all(bytes).map_err(|_| refused())?;
                file.set_permissions(std::fs::Permissions::from_mode(0o440))
                    .map_err(|_| refused())?;
                file.sync_all().map_err(|_| refused())?;
                rustix::fs::renameat(
                    &self.directory,
                    name.as_str(),
                    &self.directory,
                    "batch.json",
                )
                .map_err(|_| refused())?;
                self.directory.sync_all().map_err(|_| refused())
            })();
            if result.is_err() {
                let _ = rustix::fs::unlinkat(
                    &self.directory,
                    name.as_str(),
                    rustix::fs::AtFlags::empty(),
                );
            }
            result
        }
        pub fn read(&self, path: &Path, kind: Material, bound: usize) -> Result<Vec<u8>> {
            if bound == 0 || bound > MAX_READ {
                return Err(refused());
            }
            self.read_bounded(path, kind, bound)
        }
        /// Opt-in opaque private snapshots, including non-executable tool blobs.
        /// Existing configuration/key readers retain their original 2 MiB cap.
        pub fn read_snapshot(&self, path: &Path, bound: usize) -> Result<Vec<u8>> {
            if bound == 0 || bound > 128 << 20 {
                return Err(refused());
            }
            self.read_bounded(path, Material::Secret, bound)
        }
        fn read_bounded(&self, path: &Path, kind: Material, bound: usize) -> Result<Vec<u8>> {
            components(path)?;
            let relative = path.strip_prefix(&self.path).map_err(|_| refused())?;
            let names: Vec<_> = relative
                .components()
                .map(|part| match part {
                    Component::Normal(name) => Ok(name),
                    _ => Err(refused()),
                })
                .collect::<Result<_>>()?;
            let (last, parents) = names.split_last().ok_or_else(refused)?;
            let mut fd = self.directory.try_clone().map_err(|_| refused())?;
            // Recheck opened directories so later permission widening fails closed.
            directory(&fd, self.uid, false)?;
            for name in parents {
                fd = openat(
                    &fd,
                    *name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| refused())?
                .into();
                directory(&fd, self.uid, false)?;
            }
            let mut file: File = openat(
                &fd,
                *last,
                OFlags::RDONLY
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY,
                Mode::empty(),
            )
            .map_err(|_| refused())?
            .into();
            let before = file.metadata().map_err(|_| refused())?;
            regular(&before, self.uid, kind, bound)?;
            let mut bytes = Vec::new();
            (&mut file)
                .take(bound as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| refused())?;
            let after = file.metadata().map_err(|_| refused())?;
            regular(&after, self.uid, kind, bound)?;
            if bytes.len() > bound
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(refused());
            }
            Ok(bytes)
        }
    }
}
#[cfg(unix)]
pub use unix::Root;
#[cfg(not(unix))]
pub struct Root;
#[cfg(not(unix))]
impl Root {
    pub fn open(_path: &Path) -> Result<Self> {
        Err(refused())
    }
    pub fn uid(&self) -> u32 {
        0
    }
    pub fn read(&self, _path: &Path, _kind: Material, _bound: usize) -> Result<Vec<u8>> {
        Err(refused())
    }
    pub fn read_snapshot(&self, _path: &Path, _bound: usize) -> Result<Vec<u8>> {
        Err(refused())
    }
    pub fn stage_batch(&self, _bytes: &[u8]) -> Result<()> {
        Err(refused())
    }
}
