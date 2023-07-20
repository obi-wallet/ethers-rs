mod private_key;
pub use self::private_key::WalletError;

use crate::{Signer};
extern crate ethers_core;
use self::ethers_core::{
    k256::{
        ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature as RecoverableSignature},
        elliptic_curve::FieldBytes,
        Secp256k1,
    },
    types::Signature,
    utils::hash_message,
};
extern crate ethabi;
use self::ethabi::ethereum_types::{Address, H256, U256};

use std::fmt;

/// An Ethereum private-public key pair which can be used for signing messages.
#[derive(Clone)]
pub struct Wallet<D: PrehashSigner<(RecoverableSignature, RecoveryId)>> {
    /// The Wallet's private Key
    pub(crate) signer: D,
    /// The wallet's address
    pub(crate) address: Address,
    /// The wallet's chain id (for EIP-155)
    pub(crate) chain_id: u64,
}

impl<D: PrehashSigner<(RecoverableSignature, RecoveryId)>> Wallet<D> {
    /// Construct a new wallet with an external Signer
    pub fn new_with_signer(signer: D, address: Address, chain_id: u64) -> Self {
        Wallet { signer, address, chain_id }
    }
}

impl<D: Sync + Send + PrehashSigner<(RecoverableSignature, RecoveryId)>> Signer for Wallet<D> {
    type Error = WalletError;

    fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error> {
        let message = message.as_ref();
        let message_hash = hash_message(message);

        self.sign_hash(message_hash)
    }

    fn address(&self) -> Address {
        self.address
    }

    /// Gets the wallet's chain id
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Sets the wallet's chain_id, used in conjunction with EIP-155 signing
    fn with_chain_id<T: Into<u64>>(mut self, chain_id: T) -> Self {
        self.chain_id = chain_id.into();
        self
    }
}

impl<D: PrehashSigner<(RecoverableSignature, RecoveryId)>> Wallet<D> {
    /// Signs the provided hash.
    pub fn sign_hash(&self, hash: H256) -> Result<Signature, WalletError> {
        let (recoverable_sig, recovery_id) = self
            .signer
            .sign_prehash(hash.as_ref())
            .map_err(|e| WalletError::EcdsaError(e.to_string()))?;

        let v = u8::from(recovery_id) as u64 + 27;

        let r_bytes: FieldBytes<Secp256k1> = recoverable_sig.r().into();
        let s_bytes: FieldBytes<Secp256k1> = recoverable_sig.s().into();
        let r = U256::from_big_endian(r_bytes.as_slice());
        let s = U256::from_big_endian(s_bytes.as_slice());

        Ok(Signature { r, s, v })
    }

    /// Gets the wallet's signer
    pub fn signer(&self) -> &D {
        &self.signer
    }
}

// do not log the signer
impl<D: PrehashSigner<(RecoverableSignature, RecoveryId)>> fmt::Debug for Wallet<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("address", &self.address)
            .field("chain_Id", &self.chain_id)
            .finish()
    }
}
