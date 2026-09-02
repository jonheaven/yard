//! Dogecoin addresses (P2PKH/P2SH Base58Check), legacy tx builder, fees, JSON-RPC.

mod address;
mod error;
mod fee;
mod network;
mod rpc;
mod tx;

pub use address::{
    address_for_secret, decode_address, decode_wif, encode_wif, hash160, p2pkh_address,
};
pub use error::Error;
pub use fee::{
    estimate_legacy_size, fee_for_size, is_soft_dust, koinu_to_doge_string, parse_doge_to_koinu,
};
pub use network::Network;
pub use rpc::{RpcClient, Utxo};
pub use tx::{
    build_yard_tx, dummy_snapshot_tx, signature_hash, SealOutput, Spendable, SIGHASH_ALL,
};
