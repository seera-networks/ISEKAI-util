//! Helpers for writing secret material (private keys, account credentials,
//! PKCS#12 bundles) with owner-only filesystem permissions.

use std::path::Path;

/// Write `contents` to `path` with permissions restricted to the owner (0600).
///
/// Use this instead of [`std::fs::write`] for any private-key or credential
/// material: `fs::write` creates files with the process umask (typically
/// 0644), leaving secrets world-readable. On non-Unix platforms this falls
/// back to a plain write.
pub fn write_secret(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        // `mode` only applies when the file is newly created; tighten a
        // pre-existing file too so earlier 0644 writes are corrected.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(contents.as_ref())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// Create `path` (and any missing parents) as a directory readable only by the
/// owner (0700).
///
/// Use this for directories that hold private keys or credentials. If the
/// directory already exists its permissions are tightened to 0700, so do not
/// call this on directories that are intentionally shared with other users.
pub fn create_secret_dir(path: impl AsRef<Path>) -> std::io::Result<()> {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        // The builder's mode is masked by umask and skipped for a pre-existing
        // directory; enforce 0700 on the final directory explicitly.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}
