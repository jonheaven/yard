use crate::Error;
use serde::{Deserialize, Serialize};
use std::fmt;

/// 4-byte YARD magic: ASCII "YARD".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Magic;

pub const MAGIC_BYTES: [u8; 4] = *b"YARD";

impl Magic {
    pub fn bytes() -> [u8; 4] {
        MAGIC_BYTES
    }
}

/// Internal txid byte order is the SHA256d digest as computed (same as the
/// 32 bytes written in a serialized Dogecoin txin prevout).
/// RPC / user-facing hex is the reverse of those bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Outpoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// A seal is an outpoint that currently holds YARD state.
pub type Seal = Outpoint;

impl Outpoint {
    /// Sentinel meaning "an output of the committing L1 transaction".
    /// See YARD.md §6.2 construction note: putting the real txid in the
    /// operation would be circular with the OP_RETURN commitment.
    pub fn this_tx(vout: u32) -> Self {
        Self {
            txid: [0u8; 32],
            vout,
        }
    }

    pub fn is_this_tx(&self) -> bool {
        self.txid == [0u8; 32]
    }

    /// RPC / display txid: byte-reversed lowercase hex.
    pub fn txid_rpc_hex(&self) -> String {
        rpc_hex(&self.txid)
    }

    /// Parse a Dogecoin-RPC txid hex (display order) plus vout.
    pub fn from_rpc(txid_hex: &str, vout: u32) -> Result<Self, Error> {
        Ok(Self {
            txid: rpc_txid_to_internal(txid_hex)?,
            vout,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.txid);
        buf.extend_from_slice(&self.vout.to_le_bytes());
    }

    pub fn decode(r: &mut crate::hash::Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            txid: r.array()?,
            vout: r.u32()?,
        })
    }

    /// Resolve this-tx sentinel against the committing L1 txid (internal order).
    pub fn resolved(&self, committing_txid: &[u8; 32]) -> Self {
        if self.is_this_tx() {
            Self {
                txid: *committing_txid,
                vout: self.vout,
            }
        } else {
            *self
        }
    }

    /// True if this outpoint is output `vout` of `committing_txid`.
    pub fn is_output_of(&self, committing_txid: &[u8; 32]) -> bool {
        self.is_this_tx() || self.txid == *committing_txid
    }
}

impl fmt::Display for Outpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.txid_rpc_hex(), self.vout)
    }
}

/// SHA256d of the genesis operation bytes (including signatures).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContractId(pub [u8; 32]);

impl ContractId {
    pub fn zeros() -> Self {
        Self([0u8; 32])
    }

    pub fn is_zeros(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Wallet display: `TICK-a1b2c3d4` (first 8 hex chars of the id).
    pub fn display_with_tick(&self, tick: &str) -> String {
        format!("{}-{}", tick, hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for ContractId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Convert internal txid bytes to RPC (byte-reversed) hex.
pub fn rpc_hex(internal: &[u8; 32]) -> String {
    let mut rev = *internal;
    rev.reverse();
    hex::encode(rev)
}

/// Parse RPC txid hex into internal byte order.
pub fn rpc_txid_to_internal(rpc_hex_str: &str) -> Result<[u8; 32], Error> {
    let bytes =
        hex::decode(rpc_hex_str.trim()).map_err(|e| Error::Decode(format!("txid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Decode(format!(
            "txid must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr.reverse();
    Ok(arr)
}

/// Hex-encode internal bytes without reversing (for op hashes, contract ids).
pub fn hex_internal(b: &[u8]) -> String {
    hex::encode(b)
}
