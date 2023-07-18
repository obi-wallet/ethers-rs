#![doc = include_str!("../README.md")]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// Various utilities
pub mod utils;

#[cfg(feature = "macros")]
pub mod macros;

pub mod types;

// re-export rand to avoid potential confusion when there's rand version mismatches
pub extern crate rand;

// re-export k256
pub extern crate k256;
