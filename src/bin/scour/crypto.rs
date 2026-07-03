use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use scour_secrets::secrets::{decrypt_secrets, encrypt_secrets, parse_secrets, SecretsFormat};
use scour_secrets::{atomic_write, atomic_write_private};

use crate::cli_args::{Cli, DecryptArgs, EncryptArgs};

/// Resolve a password from multiple sources (priority order):
///   1. `--password` CLI flag
///   2. `--password-file <PATH>` (read file, check Unix permissions)
///   3. `SCOUR_SECRETS_PASSWORD` environment variable
///   4. Interactive prompt via rpassword (stderr)
pub(crate) fn resolve_password(
    password_flag: bool,
    cli_password_file: &Option<PathBuf>,
    interactive_label: &str,
) -> Result<Zeroizing<String>, String> {
    if password_flag {
        if !io::stdin().is_terminal() {
            return Err("--password requires an interactive terminal. \
                 For non-interactive use, supply the password via \
                 --password-file or the SCOUR_SECRETS_PASSWORD environment variable."
                .into());
        }
        return prompt_password(interactive_label);
    }

    if let Some(path) = cli_password_file {
        return read_password_file(path);
    }

    if let Ok(pw) = std::env::var("SCOUR_SECRETS_PASSWORD") {
        if !pw.is_empty() {
            // Remove the variable immediately after reading so the plaintext
            // password is no longer visible to child processes or subsequent
            // /proc/<pid>/environ readers.
            //
            // Safety: `remove_var` is not thread-safe on Linux when other threads
            // concurrently call getenv/setenv (POSIX data race). This call is safe
            // here because it happens during single-threaded startup, before the
            // Rayon thread pool or any library worker threads are initialised.
            // Do NOT move this call to a context where worker threads are active.
            std::env::remove_var("SCOUR_SECRETS_PASSWORD");
            eprintln!("info: using password from SCOUR_SECRETS_PASSWORD environment variable");
            return Ok(Zeroizing::new(pw));
        }
    }

    prompt_password(interactive_label)
}

/// Read a password from a file, enforcing strict Unix permissions.
#[cfg(unix)]
pub(crate) fn read_password_file(path: &Path) -> Result<Zeroizing<String>, String> {
    use nix::sys::stat::fstat;
    use std::os::unix::io::AsRawFd;

    let file = fs::File::open(path)
        .map_err(|e| format!("cannot open password file {}: {e}", path.display()))?;

    let stat = fstat(file.as_raw_fd())
        .map_err(|e| format!("cannot stat password file {}: {e}", path.display()))?;

    let mode = stat.st_mode & 0o777;
    if mode != 0o600 && mode != 0o400 {
        return Err(format!(
            "password file {} has permissions {:04o}; expected 0600 or 0400. \
             Fix with: chmod 600 {}",
            path.display(),
            mode,
            path.display(),
        ));
    }

    read_password_file_contents(path)
}

/// Read a password from a file (no permission checks on non-Unix platforms).
#[cfg(not(unix))]
pub(crate) fn read_password_file(path: &Path) -> Result<Zeroizing<String>, String> {
    eprintln!(
        "warning: password-file permission checks are only available on Unix. \
         Ensure {} is not world-readable.",
        path.display(),
    );
    read_password_file_contents(path)
}

fn read_password_file_contents(path: &Path) -> Result<Zeroizing<String>, String> {
    const MAX_PASSWORD_FILE_BYTES: u64 = 4096;
    let size = fs::metadata(path)
        .map_err(|e| format!("cannot stat password file {}: {e}", path.display()))?
        .len();
    if size > MAX_PASSWORD_FILE_BYTES {
        return Err(format!(
            "password file {} is too large ({size} bytes); expected ≤ {MAX_PASSWORD_FILE_BYTES} bytes",
            path.display(),
        ));
    }

    let mut contents = Zeroizing::new(
        fs::read_to_string(path)
            .map_err(|e| format!("cannot read password file {}: {e}", path.display()))?,
    );

    if contents.ends_with('\n') {
        contents.pop();
        if contents.ends_with('\r') {
            contents.pop();
        }
    }

    if contents.is_empty() {
        return Err(format!("password file {} is empty", path.display()));
    }

    Ok(contents)
}

/// Prompt for a password on stderr with hidden input.
pub(crate) fn prompt_password(label: &str) -> Result<Zeroizing<String>, String> {
    let pw = rpassword::prompt_password(format!("Enter {label} password: "))
        .map_err(|e| format!("failed to read password: {e}"))?;

    if pw.is_empty() {
        return Err("password must not be empty".into());
    }
    Ok(Zeroizing::new(pw))
}

/// Resolve password for the default sanitize mode.
pub(crate) fn resolve_sanitize_password(cli: &Cli) -> Result<Zeroizing<String>, String> {
    resolve_password(cli.password, &cli.password_file, "secrets decryption")
}

pub(crate) fn run_encrypt(args: &EncryptArgs) -> Result<(), (String, i32)> {
    let validate = args.validate && !args._no_validate;

    let password =
        resolve_password(args.password, &args.password_file, "encryption").map_err(|e| (e, 1))?;

    let plaintext = Zeroizing::new(
        fs::read(&args.input)
            .map_err(|e| (format!("cannot read '{}': {e}", args.input.display()), 1))?,
    );

    let format = args
        .secrets_format
        .or_else(|| SecretsFormat::from_extension(args.input.to_string_lossy().as_ref()));

    if validate {
        eprint!("Validating secrets file... ");
        match parse_secrets(&plaintext, format) {
            Ok(entries) => {
                eprintln!("OK ({} entries)", entries.len());
            }
            Err(e) => {
                eprintln!("FAILED");
                return Err((format!("validation error: {e}"), 1));
            }
        }
    }

    eprint!("Encrypting... ");
    let encrypted = encrypt_secrets(&plaintext, &password).map_err(|e| {
        eprintln!("FAILED");
        (format!("encryption failed: {e}"), 1)
    })?;

    atomic_write(&args.output, &encrypted)
        .map_err(|e| (format!("cannot write '{}': {e}", args.output.display()), 1))?;

    eprintln!("done");
    eprintln!(
        "Wrote {} bytes to '{}'",
        encrypted.len(),
        args.output.display()
    );
    eprintln!();
    eprintln!("To use with the sanitizer:");
    eprintln!(
        "  sanitize data.log -s {} --password",
        args.output.display()
    );

    Ok(())
}

pub(crate) fn run_decrypt(args: &DecryptArgs) -> Result<(), (String, i32)> {
    let password =
        resolve_password(args.password, &args.password_file, "decryption").map_err(|e| (e, 1))?;

    let encrypted = fs::read(&args.input)
        .map_err(|e| (format!("cannot read '{}': {e}", args.input.display()), 1))?;

    eprint!("Decrypting... ");
    let plaintext = decrypt_secrets(&encrypted, &password).map_err(|e| {
        eprintln!("FAILED");
        (format!("decryption failed: {e}"), 1)
    })?;

    if let Some(fmt) = args.secrets_format {
        eprint!("Validating... ");
        match parse_secrets(&plaintext, Some(fmt)) {
            Ok(entries) => {
                eprintln!("OK ({} entries)", entries.len());
            }
            Err(e) => {
                eprintln!("FAILED");
                return Err((format!("decrypted content is not valid {:?}: {e}", fmt), 1));
            }
        }
    }

    atomic_write_private(&args.output, &plaintext)
        .map_err(|e| (format!("cannot write '{}': {e}", args.output.display()), 1))?;

    eprintln!("done");
    eprintln!(
        "Wrote {} bytes to '{}'",
        plaintext.len(),
        args.output.display()
    );
    eprintln!();
    eprintln!("Remember to re-encrypt after editing:");
    eprintln!(
        "  sanitize encrypt {} {}.enc",
        args.output.display(),
        args.output.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(content: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn read_password_file_contents_strips_lf() {
        let f = write_temp(b"mysecret\n");
        let pw = read_password_file_contents(f.path()).unwrap();
        assert_eq!(pw.as_str(), "mysecret");
    }

    #[test]
    fn read_password_file_contents_strips_crlf() {
        let f = write_temp(b"mysecret\r\n");
        let pw = read_password_file_contents(f.path()).unwrap();
        assert_eq!(pw.as_str(), "mysecret");
    }

    #[test]
    fn read_password_file_contents_no_trailing_newline() {
        let f = write_temp(b"mysecret");
        let pw = read_password_file_contents(f.path()).unwrap();
        assert_eq!(pw.as_str(), "mysecret");
    }

    #[test]
    fn read_password_file_contents_empty_after_strip_is_error() {
        let f = write_temp(b"\n");
        assert!(read_password_file_contents(f.path()).is_err());
    }

    #[test]
    fn read_password_file_contents_empty_file_is_error() {
        let f = write_temp(b"");
        assert!(read_password_file_contents(f.path()).is_err());
    }

    #[test]
    fn read_password_file_contents_oversized_is_error() {
        let f = write_temp(&vec![b'x'; 4097]);
        let err = read_password_file_contents(f.path()).unwrap_err();
        assert!(err.contains("too large"), "expected 'too large' in: {err}");
    }

    #[test]
    fn read_password_file_contents_preserves_internal_newlines() {
        // Only the trailing newline is stripped; embedded newlines stay.
        let f = write_temp(b"line1\nline2\n");
        let pw = read_password_file_contents(f.path()).unwrap();
        assert_eq!(pw.as_str(), "line1\nline2");
    }
}
