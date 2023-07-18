use ethers_core::types::{
    transaction::{eip2718::TypedTransaction, eip2930::AccessListWithGasUsed},
    Address, BlockId, Bytes, Chain, Signature, TransactionRequest, U256,
};
use ethers_providers::{maybe, Middleware, MiddlewareError, PendingTransaction};
use ethers_signers::Signer;
use std::convert::TryFrom;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Clone, Debug)]
/// Middleware used for locally signing transactions, compatible with any implementer
/// of the [`Signer`] trait.
///
/// # Example
///
/// ```no_run
/// use ethers_providers::{Middleware, Provider, Http};
/// use ethers_signers::LocalWallet;
/// use ethers_middleware::SignerMiddleware;
/// use ethers_core::types::{Address, TransactionRequest};
/// use std::convert::TryFrom;
///
/// # async fn foo() -> Result<(), Box<dyn std::error::Error>> {
/// let provider = Provider::<Http>::try_from("http://localhost:8545")
///     .expect("could not instantiate HTTP Provider");
///
/// // Transactions will be signed with the private key below and will be broadcast
/// // via the eth_sendRawTransaction API)
/// let wallet: LocalWallet = "380eb0f3d505f087e438eca80bc4df9a7faa24f868e69fc0440261a0fc0567dc"
///     .parse()?;
///
/// let mut client = SignerMiddleware::new(provider, wallet);
///
/// // You can sign messages with the key
/// let signed_msg = client.sign(b"hello".to_vec(), &client.address()).await?;
///
/// // ...and sign transactions
/// let tx = TransactionRequest::pay("vitalik.eth", 100);
/// let pending_tx = client.send_transaction(tx, None).await?;
///
/// // You can `await` on the pending transaction to get the receipt with a pre-specified
/// // number of confirmations
/// let receipt = pending_tx.confirmations(6).await?;
///
/// // You can connect with other wallets at runtime via the `with_signer` function
/// let wallet2: LocalWallet = "cd8c407233c0560f6de24bb2dc60a8b02335c959a1a17f749ce6c1ccf63d74a7"
///     .parse()?;
///
/// let signed_msg2 = client.with_signer(wallet2).sign(b"hello".to_vec(), &client.address()).await?;
///
/// // This call will be made with `wallet2` since `with_signer` takes a mutable reference.
/// let tx2 = TransactionRequest::new()
///     .to("0xd8da6bf26964af9d7eed9e03e53415d37aa96045".parse::<Address>()?)
///     .value(200);
/// let tx_hash2 = client.send_transaction(tx2, None).await?;
///
/// # Ok(())
/// # }
/// ```
///
/// [`Signer`]: ethers_signers::Signer
pub struct SignerMiddleware<M, S> {
    pub(crate) inner: M,
    pub(crate) signer: S,
    pub(crate) address: Address,
}

#[derive(Error, Debug)]
/// Error thrown when the client interacts with the blockchain
pub enum SignerMiddlewareError<M: Middleware, S: Signer> {
    #[error("{0}")]
    /// Thrown when the internal call to the signer fails
    SignerError(S::Error),


    /// Thrown if the `nonce` field is missing
    #[error("no nonce was specified")]
    NonceMissing,
    /// Thrown if the `gas_price` field is missing
    #[error("no gas price was specified")]
    GasPriceMissing,
    /// Thrown if the `gas` field is missing
    #[error("no gas was specified")]
    GasMissing,
    /// Thrown if a signature is requested from a different address
    #[error("specified from address is not signer")]
    WrongSigner,
    /// Thrown if the signer's chain_id is different than the chain_id of the transaction
    #[error("specified chain_id is different than the signer's chain_id")]
    DifferentChainID,
}

impl<M: Middleware, S: Signer> MiddlewareError for SignerMiddlewareError<M, S> {
    type Inner = M::Error;

    fn from_err(src: M::Error) -> Self {
        SignerMiddlewareError::MiddlewareError(src)
    }

    fn as_inner(&self) -> Option<&Self::Inner> {
        match self {
            SignerMiddlewareError::MiddlewareError(e) => Some(e),
            _ => None,
        }
    }
}

// Helper functions for locally signing transactions
impl<M, S> SignerMiddleware<M, S>
where
    M: Middleware,
    S: Signer,
{
    /// Creates a new client from the provider and signer.
    /// Sets the address of this middleware to the address of the signer.
    /// The chain_id of the signer will not be set to the chain id of the provider. If the signer
    /// passed here is initialized with a different chain id, then the client may throw errors, or
    /// methods like `sign_transaction` may error.
    /// To automatically set the signer's chain id, see `new_with_provider_chain`.
    ///
    /// [`Middleware`] ethers_providers::Middleware
    /// [`Signer`] ethers_signers::Signer
    pub fn new(inner: M, signer: S) -> Self {
        let address = signer.address();
        SignerMiddleware { inner, signer, address }
    }

    /// Signs and returns the RLP encoding of the signed transaction.
    /// If the transaction does not have a chain id set, it sets it to the signer's chain id.
    /// Returns an error if the transaction's existing chain id does not match the signer's chain
    /// id.
    async fn sign_transaction(
        &self,
        mut tx: TypedTransaction,
    ) -> Result<Bytes, SignerMiddlewareError<M, S>> {
        // compare chain_id and use signer's chain_id if the tranasaction's chain_id is None,
        // return an error if they are not consistent
        let chain_id = self.signer.chain_id();
        match tx.chain_id() {
            Some(id) if id.as_u64() != chain_id => {
                return Err(SignerMiddlewareError::DifferentChainID)
            }
            None => {
                tx.set_chain_id(chain_id);
            }
            _ => {}
        }

        let signature =
            self.signer.sign_transaction(&tx).await.map_err(SignerMiddlewareError::SignerError)?;

        // Return the raw rlp-encoded signed transaction
        Ok(tx.rlp_signed(&signature))
    }

    /// Returns the client's address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns a reference to the client's signer
    pub fn signer(&self) -> &S {
        &self.signer
    }

    /// Builds a SignerMiddleware with the given Signer.
    #[must_use]
    pub fn with_signer(&self, signer: S) -> Self
    where
        S: Clone,
        M: Clone,
    {
        let mut this = self.clone();
        this.address = signer.address();
        this.signer = signer;
        this
    }

    /// Creates a new client from the provider and signer.
    /// Sets the address of this middleware to the address of the signer.
    /// Sets the chain id of the signer to the chain id of the inner [`Middleware`] passed in,
    /// using the [`Signer`]'s implementation of with_chain_id.
    ///
    /// [`Middleware`] ethers_providers::Middleware
    /// [`Signer`] ethers_signers::Signer
    pub async fn new_with_provider_chain(
        inner: M,
        signer: S,
    ) -> Result<Self, SignerMiddlewareError<M, S>> {
        let address = signer.address();
        let chain_id =
            inner.get_chainid().await.map_err(|e| SignerMiddlewareError::MiddlewareError(e))?;
        let signer = signer.with_chain_id(chain_id.as_u64());
        Ok(SignerMiddleware { inner, signer, address })
    }

    fn set_tx_from_if_none(&self, tx: &TypedTransaction) -> TypedTransaction {
        let mut tx = tx.clone();
        if tx.from().is_none() {
            tx.set_from(self.address);
        }
        tx
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<M, S> Middleware for SignerMiddleware<M, S>
where
    M: Middleware,
    S: Signer,
{
    type Error = SignerMiddlewareError<M, S>;
    type Provider = M::Provider;
    type Inner = M;

    fn inner(&self) -> &M {
        &self.inner
    }

    /// Returns the client's address
    fn default_sender(&self) -> Option<Address> {
        Some(self.address)
    }

    /// `SignerMiddleware` is instantiated with a signer.
    async fn is_signer(&self) -> bool {
        true
    }

    async fn sign_transaction(
        &self,
        tx: &TypedTransaction,
        _: Address,
    ) -> Result<Signature, Self::Error> {
        Ok(self.signer.sign_transaction(tx).await.map_err(SignerMiddlewareError::SignerError)?)
    }

    /// Helper for filling a transaction's nonce using the wallet
    async fn fill_transaction(
        &self,
        tx: &mut TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<(), Self::Error> {
        // get the `from` field's nonce if it's set, else get the signer's nonce
        let from = if tx.from().is_some() && tx.from() != Some(&self.address()) {
            *tx.from().unwrap()
        } else {
            self.address
        };
        tx.set_from(from);

        // get the signer's chain_id if the transaction does not set it
        let chain_id = self.signer.chain_id();
        if tx.chain_id().is_none() {
            tx.set_chain_id(chain_id);
        }

        // If a chain_id is matched to a known chain that doesn't support EIP-1559, automatically
        // change transaction to be Legacy type.
        if let Some(chain_id) = tx.chain_id() {
            let chain = Chain::try_from(chain_id.as_u64());
            if chain.unwrap_or_default().is_legacy() {
                if let TypedTransaction::Eip1559(inner) = tx {
                    let tx_req: TransactionRequest = inner.clone().into();
                    *tx = TypedTransaction::Legacy(tx_req);
                }
            }
        }

        let nonce = maybe(tx.nonce().cloned(), self.get_transaction_count(from, block)).await?;
        tx.set_nonce(nonce);
        self.inner()
            .fill_transaction(tx, block)
            .await
            .map_err(SignerMiddlewareError::MiddlewareError)?;
        Ok(())
    }

    /// Signs and broadcasts the transaction. The optional parameter `block` can be passed so that
    /// gas cost and nonce calculations take it into account. For simple transactions this can be
    /// left to `None`.
    async fn send_transaction<T: Into<TypedTransaction> + Send + Sync>(
        &self,
        tx: T,
        block: Option<BlockId>,
    ) -> Result<PendingTransaction<'_, Self::Provider>, Self::Error> {
        let mut tx = tx.into();

        // fill any missing fields
        self.fill_transaction(&mut tx, block).await?;

        // If the from address is set and is not our signer, delegate to inner
        if tx.from().is_some() && tx.from() != Some(&self.address()) {
            return self
                .inner
                .send_transaction(tx, block)
                .await
                .map_err(SignerMiddlewareError::MiddlewareError)
        }

        // if we have a nonce manager set, we should try handling the result in
        // case there was a nonce mismatch
        let signed_tx = self.sign_transaction(tx).await?;

        // Submit the raw transaction
        self.inner
            .send_raw_transaction(signed_tx)
            .await
            .map_err(SignerMiddlewareError::MiddlewareError)
    }

    /// Signs a message with the internal signer, or if none is present it will make a call to
    /// the connected node's `eth_call` API.
    async fn sign<T: Into<Bytes> + Send + Sync>(
        &self,
        data: T,
        _: &Address,
    ) -> Result<Signature, Self::Error> {
        self.signer.sign_message(data.into()).await.map_err(SignerMiddlewareError::SignerError)
    }

    async fn estimate_gas(
        &self,
        tx: &TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<U256, Self::Error> {
        let tx = self.set_tx_from_if_none(tx);
        self.inner.estimate_gas(&tx, block).await.map_err(SignerMiddlewareError::MiddlewareError)
    }

    async fn create_access_list(
        &self,
        tx: &TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<AccessListWithGasUsed, Self::Error> {
        let tx = self.set_tx_from_if_none(tx);
        self.inner
            .create_access_list(&tx, block)
            .await
            .map_err(SignerMiddlewareError::MiddlewareError)
    }

    async fn call(
        &self,
        tx: &TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<Bytes, Self::Error> {
        let tx = self.set_tx_from_if_none(tx);
        self.inner().call(&tx, block).await.map_err(SignerMiddlewareError::MiddlewareError)
    }
}
