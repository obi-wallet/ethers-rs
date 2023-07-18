#![doc = include_str!("../README.md")]
#![deny(unsafe_code, rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// The [Nonce Manager](crate::NonceManagerMiddleware) is used to locally calculate nonces instead
/// of using eth_getTransactionCount
pub mod nonce_manager;
pub use nonce_manager::NonceManagerMiddleware;

/// The [Transformer](crate::transformer::TransformerMiddleware) is used to intercept transactions
/// and transform them to be sent via various supported transformers, e.g.,
/// [DSProxy](crate::transformer::DsProxy)
pub mod transformer;

/// The [Signer](crate::SignerMiddleware) is used to locally sign transactions and messages
/// instead of using eth_sendTransaction and eth_sign
pub mod signer;
pub use signer::SignerMiddleware;

/// The [Policy](crate::PolicyMiddleware) is used to ensure transactions comply with the rules
/// configured in the `PolicyMiddleware` before sending them.
pub mod policy;
pub use policy::PolicyMiddleware;

/// The [MiddlewareBuilder](crate::MiddlewareBuilder) provides a way to compose many
/// [`Middleware`](ethers_providers::Middleware) in a concise way
pub mod builder;
pub use builder::MiddlewareBuilder;

// For macro expansions only, not public API.
// See: [#2235](https://github.com/gakonst/ethers-rs/pull/2235)

#[doc(hidden)]
#[allow(unused_extern_crates)]
extern crate self as ethers;

#[doc(hidden)]
pub use ethers_contract as contract;

#[doc(hidden)]
pub use ethers_core as core;

#[doc(hidden)]
pub use ethers_providers as providers;
