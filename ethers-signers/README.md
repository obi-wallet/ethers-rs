# ethers-signers

A unified interface for locally signing Ethereum transactions.

You can implement the `Signer` trait to extend functionality to other signers
such as Hardware Security Modules, KMS etc.

The exposed interfaces return a recoverable signature. In order to convert the
signature and the [`TransactionRequest`] to a [`Transaction`], look at the
signing middleware.

Supported signers:

-   [Private key](./src/wallet)