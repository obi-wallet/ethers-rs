mod hash;
pub use self::hash::{hash_message, id, keccak256, serialize};

/// Re-export RLP
extern crate rlp;

/// Re-export hex
extern crate hex;

extern crate ethabi;
use self::ethabi::ethereum_types::Address;
use self::ethabi::ethereum_types::FromDecStrErr;
use k256::ecdsa::SigningKey;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt,
};
extern crate thiserror;
use self::thiserror::Error;

/// I256 overflows for numbers wider than 77 units.
const OVERFLOW_I256_UNITS: usize = 77;
/// U256 overflows for numbers wider than 78 units.
const OVERFLOW_U256_UNITS: usize = 78;

#[derive(Error, Debug)]
pub enum ConversionError {
    #[error("Unknown units: {0}")]
    UnrecognizedUnits(String),
    #[error("bytes32 strings must not exceed 32 bytes in length")]
    TextTooLong,
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error(transparent)]
    InvalidFloat(#[from] std::num::ParseFloatError),
    #[error(transparent)]
    FromDecStrError(#[from] FromDecStrErr),
    #[error("Overflow parsing string")]
    ParseOverflow,
    #[error("Invalid address checksum")]
    InvalidAddressChecksum,
}

/// Converts a K256 SigningKey to an Ethereum Address
pub fn secret_key_to_address(secret_key: &SigningKey) -> Address {
    let public_key = secret_key.verifying_key();
    let public_key = public_key.to_encoded_point(/* compress = */ false);
    let public_key = public_key.as_bytes();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = keccak256(&public_key[1..]);

    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash[12..]);
    Address::from(bytes)
}
