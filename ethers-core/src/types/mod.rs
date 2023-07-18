//! Ethereum data types.

pub type Selector = [u8; 4];

// Re-export common ethereum datatypes with more specific names

/// A transaction Hash
pub use ethabi::ethereum_types::H256 as TxHash;

pub use ethabi::ethereum_types::{
    Address, BigEndianHash, Bloom, H128, H160, H256, H32, H512, H64, U128, U256, U512, U64,
};

mod address_or_bytes;
pub use address_or_bytes::AddressOrBytes;

mod path_or_string;
pub use path_or_string::PathOrString;

mod u256;
pub use u256::*;

mod bytes;
pub use self::bytes::{deserialize_bytes, serialize_bytes, Bytes, ParseBytesError};

#[cfg(feature = "celo")]
pub use block::Randomness;

mod log;
pub use log::Log;

mod signature;
pub use signature::*;

mod chain;
pub use chain::*;

mod proof;

pub use proof::*;

mod fee;
pub use fee::*;

mod other;
pub use other::OtherFields;

pub mod serde_helpers;

mod opcode;
pub use opcode::Opcode;

mod withdrawal;
pub use withdrawal::Withdrawal;
