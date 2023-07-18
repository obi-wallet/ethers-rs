/// Utilities for working with a `genesis.json` and other chain config structs.
mod genesis;
pub use genesis::{ChainConfig, CliqueConfig, EthashConfig, Genesis, GenesisAccount};

mod hash;
pub use hash::{hash_message, id, keccak256, serialize};

mod units;
use serde::{Deserialize, Deserializer};
pub use units::Units;

/// Re-export RLP
pub use rlp;

/// Re-export hex
pub use hex;

use crate::types::{Address, Bytes, H256, U256};
use ethabi::ethereum_types::FromDecStrErr;
use k256::ecdsa::SigningKey;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt,
};
use thiserror::Error;

/// I256 overflows for numbers wider than 77 units.
const OVERFLOW_I256_UNITS: usize = 77;
/// U256 overflows for numbers wider than 78 units.
const OVERFLOW_U256_UNITS: usize = 78;

// Re-export serde-json for macro usage
#[doc(hidden)]
pub use serde_json as __serde_json;

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
    #[error(transparent)]
    FromHexError(<Address as std::str::FromStr>::Err),
}

/// 1 Ether = 1e18 Wei == 0x0de0b6b3a7640000 Wei
pub const WEI_IN_ETHER: U256 = U256([0x0de0b6b3a7640000, 0x0, 0x0, 0x0]);

/// The number of blocks from the past for which the fee rewards are fetched for fee estimation.
pub const EIP1559_FEE_ESTIMATION_PAST_BLOCKS: u64 = 10;
/// The default percentile of gas premiums that are fetched for fee estimation.
pub const EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE: f64 = 5.0;
/// The default max priority fee per gas, used in case the base fee is within a threshold.
pub const EIP1559_FEE_ESTIMATION_DEFAULT_PRIORITY_FEE: u64 = 3_000_000_000;
/// The threshold for base fee below which we use the default priority fee, and beyond which we
/// estimate an appropriate value for priority fee.
pub const EIP1559_FEE_ESTIMATION_PRIORITY_FEE_TRIGGER: u64 = 100_000_000_000;
/// The threshold max change/difference (in %) at which we will ignore the fee history values
/// under it.
pub const EIP1559_FEE_ESTIMATION_THRESHOLD_MAX_CHANGE: i64 = 200;

/// The address for an Ethereum contract is deterministically computed from the
/// address of its creator (sender) and how many transactions the creator has
/// sent (nonce). The sender and nonce are RLP encoded and then hashed with Keccak-256.
pub fn get_contract_address(sender: impl Into<Address>, nonce: impl Into<U256>) -> Address {
    let mut stream = rlp::RlpStream::new();
    stream.begin_list(2);
    stream.append(&sender.into());
    stream.append(&nonce.into());

    let hash = keccak256(&stream.out());

    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash[12..]);
    Address::from(bytes)
}

/// Returns the CREATE2 address of a smart contract as specified in
/// [EIP1014](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1014.md)
///
/// keccak256( 0xff ++ senderAddress ++ salt ++ keccak256(init_code))[12..]
pub fn get_create2_address(
    from: impl Into<Address>,
    salt: impl AsRef<[u8]>,
    init_code: impl AsRef<[u8]>,
) -> Address {
    let init_code_hash = keccak256(init_code.as_ref());
    get_create2_address_from_hash(from, salt, init_code_hash)
}

/// Returns the CREATE2 address of a smart contract as specified in
/// [EIP1014](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1014.md),
/// taking the pre-computed hash of the init code as input.
///
/// keccak256( 0xff ++ senderAddress ++ salt ++ keccak256(init_code))[12..]
///
/// # Example
///
/// Calculate the address of a UniswapV3 pool.
///
/// ```
/// use ethers_core::{
///     abi,
///     abi::Token,
///     types::{Address, Bytes, U256},
///     utils::{get_create2_address_from_hash, keccak256},
/// };
///
/// let init_code_hash = hex::decode("e34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54").unwrap();
/// let factory: Address = "0x1F98431c8aD98523631AE4a59f267346ea31F984"
///     .parse()
///     .unwrap();
/// let token0: Address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
///     .parse()
///     .unwrap();
/// let token1: Address = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
///     .parse()
///     .unwrap();
/// let fee = U256::from(500_u64);
///
/// // abi.encode(token0 as address, token1 as address, fee as uint256)
/// let input = abi::encode(&[
///     Token::Address(token0),
///     Token::Address(token1),
///     Token::Uint(fee),
/// ]);
///
/// // keccak256(abi.encode(token0, token1, fee))
/// let salt = keccak256(&input);
/// let pool_address = get_create2_address_from_hash(factory, salt, init_code_hash);
///
/// assert_eq!(
///     pool_address,
///     "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640" // USDC/ETH pool address
///         .parse()
///         .unwrap()
/// );
/// ```
pub fn get_create2_address_from_hash(
    from: impl Into<Address>,
    salt: impl AsRef<[u8]>,
    init_code_hash: impl AsRef<[u8]>,
) -> Address {
    let from = from.into();
    let salt = salt.as_ref();
    let init_code_hash = init_code_hash.as_ref();

    let mut bytes = Vec::with_capacity(1 + 20 + salt.len() + init_code_hash.len());
    bytes.push(0xff);
    bytes.extend_from_slice(from.as_bytes());
    bytes.extend_from_slice(salt);
    bytes.extend_from_slice(init_code_hash);

    let hash = keccak256(bytes);

    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash[12..]);
    Address::from(bytes)
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

/// Encodes an Ethereum address to its [EIP-55] checksum.
///
/// You can optionally specify an [EIP-155 chain ID] to encode the address using the [EIP-1191]
/// extension.
///
/// [EIP-55]: https://eips.ethereum.org/EIPS/eip-55
/// [EIP-155 chain ID]: https://eips.ethereum.org/EIPS/eip-155
/// [EIP-1191]: https://eips.ethereum.org/EIPS/eip-1191
pub fn to_checksum(addr: &Address, chain_id: Option<u8>) -> String {
    let prefixed_addr = match chain_id {
        Some(chain_id) => format!("{chain_id}0x{addr:x}"),
        None => format!("{addr:x}"),
    };
    let hash = hex::encode(keccak256(prefixed_addr));
    let hash = hash.as_bytes();

    let addr_hex = hex::encode(addr.as_bytes());
    let addr_hex = addr_hex.as_bytes();

    addr_hex.iter().zip(hash).fold("0x".to_owned(), |mut encoded, (addr, hash)| {
        encoded.push(if *hash >= 56 {
            addr.to_ascii_uppercase() as char
        } else {
            addr.to_ascii_lowercase() as char
        });
        encoded
    })
}

/// Parses an [EIP-1191](https://eips.ethereum.org/EIPS/eip-1191) checksum address.
///
/// Returns `Ok(address)` if the checksummed address is valid, `Err()` otherwise.
/// If `chain_id` is `None`, falls back to [EIP-55](https://eips.ethereum.org/EIPS/eip-55) address checksum method
pub fn parse_checksummed(addr: &str, chain_id: Option<u8>) -> Result<Address, ConversionError> {
    let addr = addr.strip_prefix("0x").unwrap_or(addr);
    let address: Address = addr.parse().map_err(ConversionError::FromHexError)?;
    let checksum_addr = to_checksum(&address, chain_id);

    if checksum_addr.strip_prefix("0x").unwrap_or(&checksum_addr) == addr {
        Ok(address)
    } else {
        Err(ConversionError::InvalidAddressChecksum)
    }
}

/// Returns a bytes32 string representation of text. If the length of text exceeds 32 bytes,
/// an error is returned.
pub fn format_bytes32_string(text: &str) -> Result<[u8; 32], ConversionError> {
    let str_bytes: &[u8] = text.as_bytes();
    if str_bytes.len() > 32 {
        return Err(ConversionError::TextTooLong)
    }

    let mut bytes32: [u8; 32] = [0u8; 32];
    bytes32[..str_bytes.len()].copy_from_slice(str_bytes);

    Ok(bytes32)
}

/// Returns the decoded string represented by the bytes32 encoded data.
pub fn parse_bytes32_string(bytes: &[u8; 32]) -> Result<&str, ConversionError> {
    let mut length = 0;
    while length < 32 && bytes[length] != 0 {
        length += 1;
    }

    Ok(std::str::from_utf8(&bytes[..length])?)
}

/// Converts a Bytes value into a H256, accepting inputs that are less than 32 bytes long. These
/// inputs will be left padded with zeros.
pub fn from_bytes_to_h256<'de, D>(bytes: Bytes) -> Result<H256, D::Error>
where
    D: Deserializer<'de>,
{
    if bytes.0.len() > 32 {
        return Err(serde::de::Error::custom("input too long to be a H256"))
    }

    // left pad with zeros to 32 bytes
    let mut padded = [0u8; 32];
    padded[32 - bytes.0.len()..].copy_from_slice(&bytes.0);

    // then convert to H256 without a panic
    Ok(H256::from_slice(&padded))
}

/// Deserializes the input into an Option<HashMap<H256, H256>>, using from_unformatted_hex to
/// deserialize the keys and values.
pub fn from_unformatted_hex_map<'de, D>(
    deserializer: D,
) -> Result<Option<HashMap<H256, H256>>, D::Error>
where
    D: Deserializer<'de>,
{
    let map = Option::<HashMap<Bytes, Bytes>>::deserialize(deserializer)?;
    match map {
        Some(mut map) => {
            let mut res_map = HashMap::new();
            for (k, v) in map.drain() {
                let k_deserialized = from_bytes_to_h256::<'de, D>(k)?;
                let v_deserialized = from_bytes_to_h256::<'de, D>(v)?;
                res_map.insert(k_deserialized, v_deserialized);
            }
            Ok(Some(res_map))
        }
        None => Ok(None),
    }
}

fn base_fee_surged(base_fee_per_gas: U256) -> U256 {
    if base_fee_per_gas <= U256::from(40_000_000_000u64) {
        base_fee_per_gas * 2
    } else if base_fee_per_gas <= U256::from(100_000_000_000u64) {
        base_fee_per_gas * 16 / 10
    } else if base_fee_per_gas <= U256::from(200_000_000_000u64) {
        base_fee_per_gas * 14 / 10
    } else {
        base_fee_per_gas * 12 / 10
    }
}

/// A bit of hack to find an unused TCP port.
///
/// Does not guarantee that the given port is unused after the function exists, just that it was
/// unused before the function started (i.e., it does not reserve a port).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn unused_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("Failed to create TCP listener to find unused port");

    let local_addr =
        listener.local_addr().expect("Failed to read TCP listener local_addr to find unused port");
    local_addr.port()
}