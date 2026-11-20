//! Optional persistent CRL cache.
//!
//! Each file holds one CRL and a short text header. The file name is the
//! SHA-256 digest of the distribution point URL. The header records the URL, the
//! SHA-256 digest of the CRL, and optionally the issuer key that verified the
//! CRL. A file is written to a temporary name and then renamed, so a reader
//! never sees a partial file.
//!
//! The cache is not trusted. The loader rejects a file whose name, digest, or
//! CRL does not match. A recorded key only lets the verifier check the CRL
//! signature early. A connection uses the CRL only when that key is the key of
//! the issuer certificate in its verified path.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};

use crate::crl::{Crl, digest, hex};

const MAGIC: &str = "tacacsrs-crl 1";

/// Size limit of the text header.
const HEADER_LIMIT: usize = 16 * 1024;

const EXTENSION: &str = "crl";

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One CRL loaded from the cache.
pub(crate) struct CachedFile {
    pub(crate) url: String,
    pub(crate) crl: Crl,
    pub(crate) key_der: Option<Vec<u8>>,
}

/// Returns the cache file name for `url`.
pub(crate) fn file_name(url: &str) -> Result<String> {
    Ok(format!("{}.{EXTENSION}", hex(&digest(url.as_bytes())?)))
}

/// Writes `crl` for `url` into `directory`.
pub(crate) fn write(
    directory: &Path,
    url: &str,
    crl: &Crl,
    key_der: Option<&[u8]>,
    limit: u64,
) -> Result<()> {
    if u64::try_from(crl.der.len()).unwrap_or(u64::MAX) > limit {
        log::debug!("Did not cache the CRL from {url} because it exceeds the size limit");
        return Ok(());
    }
    fs::create_dir_all(directory)
        .with_context(|| format!("Could not create the CRL cache {}", directory.display()))?;
    let name = file_name(url)?;
    let mut content = format!("{MAGIC}\nurl {url}\nsha256 {}\n", hex(&crl.digest));
    if let Some(key) = key_der {
        content.push_str(&format!("key {}\n", hex(key)));
    }
    content.push('\n');
    let mut content = content.into_bytes();
    content.extend_from_slice(&crl.der);
    let temporary = directory.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(&content)?;
        file.sync_all()?;
        fs::rename(&temporary, directory.join(&name))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.with_context(|| format!("Could not write the cached CRL {name}"))
}

/// Loads all valid cache files from `directory` and removes invalid files.
pub(crate) fn load(directory: &Path, limit: u64) -> Vec<CachedFile> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            log::debug!("Could not read the CRL cache {}: {error}", directory.display());
            return Vec::new();
        }
    };
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
        else {
            continue;
        };
        if name.starts_with('.') {
            if name.ends_with(".tmp") {
                let _ = fs::remove_file(&path);
            }
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some(EXTENSION) {
            continue;
        }
        match read(&path, &name, limit) {
            Ok(file) => files.push(file),
            Err(error) => {
                log::warn!("Rejected the cached CRL {}: {error:#}", path.display());
                let _ = fs::remove_file(&path);
            }
        }
    }
    files
}

fn read(path: &PathBuf, name: &str, limit: u64) -> Result<CachedFile> {
    let size = fs::metadata(path)?.len();
    let header_limit = u64::try_from(HEADER_LIMIT).unwrap_or(u64::MAX);
    ensure!(size <= limit.saturating_add(header_limit), "The file exceeds the CRL size limit");
    let data = fs::read(path)?;
    let end = data
        .windows(2)
        .take(HEADER_LIMIT)
        .position(|pair| pair == b"\n\n")
        .context("The header is missing")?;
    let header = std::str::from_utf8(&data[..end]).context("The header is not text")?;
    let body = &data[end + 2..];
    let mut lines = header.lines();
    ensure!(lines.next() == Some(MAGIC), "Unknown cache format");
    let mut url = None;
    let mut recorded = None;
    let mut key_der = None;
    for line in lines {
        let (field, value) = line.split_once(' ').context("Invalid header line")?;
        match field {
            "url" => url = Some(value.to_owned()),
            "sha256" => recorded = Some(value.to_owned()),
            "key" => key_der = Some(unhex(value)?),
            _ => bail!("Unknown header field"),
        }
    }
    let url = url.context("The URL is missing")?;
    ensure!(file_name(&url)? == name, "The file name does not match the URL");
    ensure!(
        recorded.as_deref() == Some(hex(&digest(body)?).as_str()),
        "The CRL digest does not match"
    );
    ensure!(
        u64::try_from(body.len()).unwrap_or(u64::MAX) <= limit,
        "The CRL exceeds the size limit"
    );
    let crl = Crl::parse(body)?;
    ensure!(crl.der == body, "The cached CRL is not DER");
    Ok(CachedFile { url, crl, key_der })
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    ensure!(text.len().is_multiple_of(2), "Invalid hexadecimal text");
    (0..text.len())
        .step_by(2)
        .map(|index| {
            text.get(index..index + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .context("Invalid hexadecimal text")
        })
        .collect()
}
