#![doc = include_str!("../README.md")]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// Various utilities
pub mod utils;

#[cfg(feature = "macros")]
pub mod macros;

pub mod types;

// re-export k256
pub extern crate k256;
