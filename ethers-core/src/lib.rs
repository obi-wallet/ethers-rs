#![doc = include_str!("../README.md")]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod types;

/// Various utilities
pub mod utils;

#[cfg(feature = "macros")]
pub mod macros;

// re-export rand to avoid potential confusion when there's rand version mismatches
pub use rand;

// re-export k256
pub use k256;
