use ethers::{
    core::{types::TransactionRequest, utils::Anvil},
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
};
use eyre::Result;
use std::convert::TryFrom;

#[tokio::main]
async fn main() -> Result<()> {
    let anvil = Anvil::new().spawn();

    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let wallet2: LocalWallet = anvil.keys()[1].clone().into();

    // connect to the network
    let provider = Provider::<Http>::try_from(anvil.endpoint())?;

    // connect the wallet to the provider
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id()));

    // craft the transaction
    let tx = TransactionRequest::new().to(wallet2.address()).value(10000);

    Ok(())
}
