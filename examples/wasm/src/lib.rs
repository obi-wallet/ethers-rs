use ethers::{
    prelude::{Provider, SignerMiddleware},
    providers::{Middleware, Ws},
    signers::Signer,
};
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use web_sys::console;

pub mod utils;

macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}