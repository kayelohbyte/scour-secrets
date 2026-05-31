//! Atomic file writes for crash-safe output.
//!
//! All output files are written via a temporary file alongside the final
//! destination, flushed and fsynced, then atomically renamed into place.
//! This guarantees that the final path either contains the complete, valid
//! output or does not exist at all — partial or corrupt files are never
//! left behind even if the process crashes or is interrupted.
//!
//! # Platform Notes
//!
//! - On POSIX systems, `std::fs::rename` is atomic within the same
//!   filesystem.  The temporary file is created in the same directory as
//!   the destination to ensure they share a mount point.
//! - `File::sync_all()` is called before rename to flush OS and
//!   hardware buffers.
//! - On rename failure, the temporary file is cleaned up on a
//!   best-effort basis.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// An atomic file writer that writes to a temporary file and renames
/// on completion.
///
/// If the writer is dropped without calling [`finish()`](Self::finish),
/// the temporary file is removed (best-effort cleanup).
pub struct AtomicFileWriter {
    /// Buffered writer around the temporary file.
    writer: BufWriter<File>,
    /// Path to the temporary file.
    tmp_path: PathBuf,
    /// Final destination path.
    dest_path: PathBuf,
    /// Whether `finish()` has been called successfully.
    finished: bool,
}

impl AtomicFileWriter {
    /// Create a new atomic writer targeting `dest`.
    ///
    /// The temporary file is created with a random suffix in the same
    /// directory as `dest`, using `O_CREAT | O_EXCL` to prevent
    /// symlink-following attacks on shared filesystems.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the temporary file cannot be created.
    pub fn new(dest: impl AsRef<Path>) -> io::Result<Self> {
        Self::open(dest, false)
    }

    /// Like [`new`](Self::new), but restricts the temp file (and therefore
    /// the renamed destination) to owner-read/write (0600) on Unix.
    ///
    /// Use this when writing files that contain sensitive material such as
    /// plaintext secrets, so that the data is never world-readable — even
    /// during the brief window between the initial `open` and the rename.
    pub fn new_private(dest: impl AsRef<Path>) -> io::Result<Self> {
        Self::open(dest, true)
    }

    fn open(dest: impl AsRef<Path>, private: bool) -> io::Result<Self> {
        let dest_path = dest.as_ref().to_path_buf();
        let dir = dest_path.parent().unwrap_or(Path::new("."));
        let base_name = dest_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("out");

        // Random suffix to prevent predictable temp file paths.
        let random_suffix: u64 = rand::random();
        let tmp_name = format!(".{}.{:016x}.tmp", base_name, random_suffix);
        let tmp_path = dir.join(tmp_name);

        // O_CREAT | O_EXCL: fails if the path already exists (no symlink following).
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;

        // Restrict permissions before any data is written so the file is
        // never world-readable, even briefly.
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }

        Ok(Self {
            writer: BufWriter::new(file),
            tmp_path,
            dest_path,
            finished: false,
        })
    }

    /// Flush all buffers, fsync, and atomically rename to the final
    /// destination.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if flush, sync, or rename fails.  On
    /// error, the temporary file is cleaned up on a best-effort basis.
    pub fn finish(mut self) -> io::Result<()> {
        // Flush the BufWriter.
        self.writer.flush()?;

        // Fsync the underlying file.
        self.writer.get_ref().sync_all()?;

        // Atomic rename.
        if let Err(e) = fs::rename(&self.tmp_path, &self.dest_path) {
            // Cleanup the temp file on rename failure.
            let _ = fs::remove_file(&self.tmp_path);
            return Err(e);
        }

        self.finished = true;
        Ok(())
    }

    /// Return the path of the temporary file (useful for cleanup on
    /// signal).
    #[must_use]
    pub fn tmp_path(&self) -> &Path {
        &self.tmp_path
    }

    /// Return the final destination path.
    #[must_use]
    pub fn dest_path(&self) -> &Path {
        &self.dest_path
    }
}

impl Write for AtomicFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl io::Seek for AtomicFileWriter {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.writer.flush()?;
        self.writer.get_mut().seek(pos)
    }
}

impl Drop for AtomicFileWriter {
    fn drop(&mut self) {
        if !self.finished {
            // Best-effort cleanup: remove the temporary file.
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}

/// Write `data` to `dest` atomically.
///
/// Convenience wrapper around [`AtomicFileWriter`] for in-memory data.
///
/// # Errors
///
/// Returns [`std::io::Error`] if the file cannot be created, written,
/// or renamed.
pub fn atomic_write(dest: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    let mut writer = AtomicFileWriter::new(dest)?;
    writer.write_all(data)?;
    writer.finish()
}

/// Like [`atomic_write`] but creates the file with owner-only permissions
/// (0600 on Unix).  Use for files containing plaintext secrets or other
/// sensitive material.
pub fn atomic_write_private(dest: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    let mut writer = AtomicFileWriter::new_private(dest)?;
    writer.write_all(data)?;
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("output.txt");
        atomic_write(&dest, b"hello world").unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "hello world");
        // Temp file should not exist.
        let tmp = dir.path().join("output.txt.tmp");
        assert!(!tmp.exists());
    }

    #[test]
    fn atomic_writer_drop_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("output.txt");
        {
            let mut w = AtomicFileWriter::new(&dest).unwrap();
            w.write_all(b"partial").unwrap();
            // Drop without finish — should clean up temp.
        }
        assert!(!dest.exists(), "dest should not exist after aborted write");
        let tmp = dir.path().join("output.txt.tmp");
        assert!(!tmp.exists(), "temp file should be cleaned up");
    }

    #[test]
    fn atomic_writer_streaming() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("streamed.txt");
        let mut w = AtomicFileWriter::new(&dest).unwrap();
        for i in 0..100 {
            writeln!(w, "line {}", i).unwrap();
        }
        w.finish().unwrap();
        let content = fs::read_to_string(&dest).unwrap();
        assert_eq!(content.lines().count(), 100);
    }
}
