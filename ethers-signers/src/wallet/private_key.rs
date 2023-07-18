//! Specific helper functions for loading an offline K256 Private Key stored on disk
use super::Wallet;

extern crate ethers_core;
use self::ethers_core::{
    k256::ecdsa::{self, SigningKey},
    rand::{CryptoRng, Rng},
    utils::secret_key_to_address
};
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::{str::FromStr, convert::TryFrom};
extern crate thiserror;
use self::thiserror::Error;

#[derive(Error, Debug)]
/// Error thrown by the Wallet module
pub enum WalletError {
    #[error(transparent)]
    EcdsaError(#[from] ecdsa::Error),
    /// Error propagated from the hex crate.
    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
    /// Error propagated by IO operations
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// Error type from Eip712Error message
    #[error("error encoding eip712 struct: {0:?}")]
    Eip712Error(String),
}

impl Wallet<SigningKey> {
    /// Creates a new random keypair seeded with the provided RNG
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let signer = SigningKey::random(rng);
        let address = secret_key_to_address(&signer);
        Self { signer, address, chain_id: 1 }
    }

    /// Creates a new Wallet instance from a raw scalar value (big endian).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        let signer = SigningKey::from_bytes(bytes.into())?;
        let address = secret_key_to_address(&signer);
        Ok(Self { signer, address, chain_id: 1 })
    }
}

impl PartialEq for Wallet<SigningKey> {
    fn eq(&self, other: &Self) -> bool {
        self.signer.to_bytes().eq(&other.signer.to_bytes()) &&
            self.address == other.address &&
            self.chain_id == other.chain_id
    }
}

impl From<SigningKey> for Wallet<SigningKey> {
    fn from(signer: SigningKey) -> Self {
        let address = secret_key_to_address(&signer);

        Self { signer, address, chain_id: 1 }
    }
}

use ethers_core::k256::SecretKey as K256SecretKey;

impl From<K256SecretKey> for Wallet<SigningKey> {
    fn from(key: K256SecretKey) -> Self {
        let signer = key.into();
        let address = secret_key_to_address(&signer);

        Self { signer, address, chain_id: 1 }
    }
}

impl FromStr for Wallet<SigningKey> {
    type Err = WalletError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let src = src.strip_prefix("0x").or_else(|| src.strip_prefix("0X")).unwrap_or(src);
        let src = hex::decode(src)?;

        if src.len() != 32 {
            return Err(WalletError::HexError(hex::FromHexError::InvalidStringLength))
        }

        let sk = SigningKey::from_bytes(src.as_slice().into())?;
        Ok(sk.into())
    }
}

impl TryFrom<&str> for Wallet<SigningKey> {
    type Error = WalletError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for Wallet<SigningKey> {
    type Error = WalletError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::{LocalWallet, Signer};
    extern crate ethabi;
    use self::ethabi::ethereum_types::Address;

    #[test]
    fn parse_pk() {
        let s = "6f142508b4eea641e33cb2a0161221105086a84584c74245ca463a49effea30b";
        let _pk: Wallet<SigningKey> = s.parse().unwrap();
    }

    #[test]
    fn parse_short_key() {
        let s = "6f142508b4eea641e33cb2a0161221105086a84584c74245ca463a49effea3";
        assert!(s.len() < 64);
        let pk = s.parse::<LocalWallet>().unwrap_err();
        match pk {
            WalletError::HexError(hex::FromHexError::InvalidStringLength) => {}
            _ => panic!("Unexpected error"),
        }
    }

    #[test]
    fn key_to_address() {
        let wallet: Wallet<SigningKey> =
            "0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap();
        assert_eq!(
            wallet.address,
            Address::from_str("7E5F4552091A69125d5DfCb7b8C2659029395Bdf").expect("Decoding failed")
        );

        let wallet: Wallet<SigningKey> =
            "0000000000000000000000000000000000000000000000000000000000000002".parse().unwrap();
        assert_eq!(
            wallet.address,
            Address::from_str("2B5AD5c4795c026514f8317c7a215E218DcCD6cF").expect("Decoding failed")
        );

        let wallet: Wallet<SigningKey> =
            "0000000000000000000000000000000000000000000000000000000000000003".parse().unwrap();
        assert_eq!(
            wallet.address,
            Address::from_str("6813Eb9362372EEF6200f3b1dbC3f819671cBA69").expect("Decoding failed")
        );
    }

    #[test]
    fn key_from_bytes() {
        let wallet: Wallet<SigningKey> =
            "0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap();

        let key_as_bytes = wallet.signer.to_bytes();
        let wallet_from_bytes = Wallet::from_bytes(&key_as_bytes).unwrap();

        assert_eq!(wallet.address, wallet_from_bytes.address);
        assert_eq!(wallet.chain_id, wallet_from_bytes.chain_id);
        assert_eq!(wallet.signer, wallet_from_bytes.signer);
    }

}
