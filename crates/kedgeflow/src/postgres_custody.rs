//! Explicit descriptor/mode custody for SQL target files; no OS isolation claim.
use crate::{
    error::{Error, Result},
    postgres_config::PostgresTargetConfig,
    postgres_target::TargetService,
    tls,
};
use std::{path::Path, sync::Arc};
pub const PROFILE: &str = "KF-POSTGRES-CUSTODY-0.1-draft";
pub struct LoadedTarget {
    pub config: PostgresTargetConfig,
    pub tls: Arc<rustls::ServerConfig>,
    pub service: Arc<TargetService>,
    pub effective_uid: u32,
}
fn refused() -> Error {
    Error::Refused("protected SQL file custody rejected".into())
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
        io::Read,
        os::unix::fs::MetadataExt,
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
        pub fn read(&self, path: &Path, kind: Material, bound: usize) -> Result<Vec<u8>> {
            if bound == 0 || bound > 1 << 20 {
                return Err(refused());
            }
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
}
impl LoadedTarget {
    pub fn load(root: &Path, config_path: &Path) -> Result<Self> {
        Self::load_with_peer(root, config_path, None)
    }
    pub fn load_with_peer(root: &Path, config_path: &Path, peer_uid: Option<u32>) -> Result<Self> {
        let root = Root::open(root)?;
        let config =
            PostgresTargetConfig::decode(&root.read(config_path, Material::Public, 1 << 20)?)?;
        let cert = root.read(&config.certificate, Material::Public, 1 << 20)?;
        let key = root.read(&config.private_key, Material::Secret, 65536)?;
        let ca = root.read(&config.workload_ca, Material::Public, 1 << 20)?;
        let token = root.read(&config.query_token_file, Material::Secret, 65536)?;
        let token = std::str::from_utf8(&token).map_err(|_| refused())?.trim();
        let tls = tls::server_config_pem(&cert, &key, &ca)?;
        let service = config.service_with_peer(token, peer_uid)?;
        Ok(Self {
            config,
            tls,
            service,
            effective_uid: root.uid(),
        })
    }
}
