//! Parse ABI artifacts from different sources.

// TODO: Support `online` for WASM

#[cfg(all(feature = "online", not(target_arch = "wasm32")))]
mod online;
#[cfg(all(feature = "online", not(target_arch = "wasm32")))]
pub use online::Explorer;

use crate::util;
use eyre::{Error, Result};
use std::{env, fs, path::PathBuf, str::FromStr};

/// A source of an Ethereum smart contract's ABI.
///
/// See [`parse`][#method.parse] for more information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Source {
    /// A raw ABI string.
    String(String),

    /// An ABI located on the local file system.
    Local(PathBuf),

    /// An address of a smart contract address verified at a supported blockchain explorer.
    #[cfg(all(feature = "online", not(target_arch = "wasm32")))]
    Explorer(Explorer, ethers_core::types::Address),

    /// The package identifier of an npm package with a path to a Truffle artifact or ABI to be
    /// retrieved from `unpkg.io`.
    #[cfg(all(feature = "online", not(target_arch = "wasm32")))]
    Npm(String),

    /// An ABI to be retrieved over HTTP(S).
    #[cfg(all(feature = "online", not(target_arch = "wasm32")))]
    Http(url::Url),
}

impl Default for Source {
    fn default() -> Self {
        Self::String("[]".to_string())
    }
}

impl FromStr for Source {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Source::parse(s)
    }
}

impl Source {
    /// Parses an ABI from a source.
    ///
    /// This method accepts the following:
    ///
    /// - `{ ... }` or `[ ... ]`: A raw or human-readable ABI object or array of objects.
    ///
    /// - `relative/path/to/Contract.json`: a relative path to an ABI JSON file. This relative path
    ///   is rooted in the current working directory.
    ///
    /// - `/absolute/path/to/Contract.json` or `file:///absolute/path/to/Contract.json`: an absolute
    ///   path or file URL to an ABI JSON file.
    ///
    /// If the `online` feature is enabled:
    ///
    /// - `npm:@org/package@1.0.0/path/to/contract.json`: A npmjs package with an optional version
    ///   and path (defaulting to the latest version and `index.js`), retrieved through `unpkg.io`.
    ///
    /// - `http://...`: an HTTP URL to a contract ABI. <br> Note: either the `rustls` or `openssl`
    ///   feature must be enabled to support *HTTPS* URLs.
    ///
    /// - `<name>:<address>`, `<chain>:<address>` or `<url>/.../<address>`: an address or URL of a
    ///   verified contract on a blockchain explorer. <br> Supported explorers and their respective
    ///   chain:
    ///   - `etherscan`   -> `mainnet`
    ///   - `bscscan`     -> `bsc`
    ///   - `polygonscan` -> `polygon`
    ///   - `snowtrace`   -> `avalanche`
    pub fn parse(source: impl AsRef<str>) -> Result<Self> {
        let source = source.as_ref().trim();
        match source.chars().next() {
            Some('[' | '{') => Ok(Self::String(source.to_string())),

            #[cfg(any(not(feature = "online"), target_arch = "wasm32"))]
            _ => Ok(Self::local(source)?),

            #[cfg(all(feature = "online", not(target_arch = "wasm32")))]
            Some('/') => Self::local(source),
            #[cfg(all(feature = "online", not(target_arch = "wasm32")))]
            _ => Self::parse_online(source),
        }
    }

    /// Creates a local filesystem source from a path string.
    pub fn local(path: impl AsRef<str>) -> Result<Self> {
        // resolve env vars
        let path = path.as_ref().trim_start_matches("file://");
        let mut resolved = util::resolve_path(path)?;

        if resolved.is_relative() {
            // set root at manifest dir, if the path exists
            if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
                let new = PathBuf::from(manifest_dir).join(&resolved);
                if new.exists() {
                    resolved = new;
                }
            }
        }

        // canonicalize
        if let Ok(canonicalized) = dunce::canonicalize(&resolved) {
            resolved = canonicalized;
        } else {
            let path = resolved.display().to_string();
            let err = if path.contains(':') {
                eyre::eyre!("File does not exist: {path}\nYou may need to enable the `online` feature to parse this source.")
            } else {
                eyre::eyre!("File does not exist: {path}")
            };
            return Err(err)
        }

        Ok(Source::Local(resolved))
    }

    /// Returns `true` if `self` is `String`.
    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }

    /// Returns `self` as `String`.
    pub fn as_string(&self) -> Option<&String> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Returns `true` if `self` is `Local`.
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local(_))
    }

    /// Returns `self` as `Local`.
    pub fn as_local(&self) -> Option<&PathBuf> {
        match self {
            Self::Local(p) => Some(p),
            _ => None,
        }
    }

    /// Retrieves the source JSON of the artifact this will either read the JSON from the file
    /// system or retrieve a contract ABI from the network depending on the source type.
    pub fn get(&self) -> Result<String> {
        match self {
            Self::Local(path) => Ok(fs::read_to_string(path)?),
            Self::String(abi) => Ok(abi.clone()),

            #[cfg(all(feature = "online", not(target_arch = "wasm32")))]
            _ => self.get_online(),
        }
    }
}
