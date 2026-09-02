use crate::operation::Operation;
use crate::{sha256d, Error, MAGIC_BYTES};

pub const COMMITMENT_LEN: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommitmentKind {
    Single = 0x01,
    Merkle = 0x02,
}

impl CommitmentKind {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0x01 => Ok(Self::Single),
            0x02 => Ok(Self::Merkle),
            _ => Err(Error::Decode(format!("unknown commitment kind 0x{v:02x}"))),
        }
    }
}

/// 40-byte v1 OP_RETURN payload. Trailing bytes after this in the push are
/// rejected (strict v1 — no "cursed" envelopes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub version: u8,
    pub kind: CommitmentKind,
    pub root: [u8; 32],
    pub flags: u8,
}

impl Commitment {
    pub fn encode(&self) -> [u8; COMMITMENT_LEN] {
        let mut p = [0u8; COMMITMENT_LEN];
        p[0..4].copy_from_slice(&MAGIC_BYTES);
        p[4] = 0x01;
        p[5] = self.kind as u8;
        p[6..38].copy_from_slice(&self.root);
        p[38] = self.flags;
        p[39] = 0x00;
        p
    }

    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() != COMMITMENT_LEN {
            return Err(Error::Decode(format!(
                "commitment payload is {} bytes, want {COMMITMENT_LEN} (trailing bytes rejected)",
                payload.len()
            )));
        }
        if payload[0..4] != MAGIC_BYTES {
            return Err(Error::Decode("commitment magic is not YARD".into()));
        }
        if payload[4] != 0x01 {
            return Err(Error::Decode(format!(
                "commitment version {} != 1",
                payload[4]
            )));
        }
        let kind = CommitmentKind::from_u8(payload[5])?;
        let mut root = [0u8; 32];
        root.copy_from_slice(&payload[6..38]);
        let flags = payload[38];
        // bits 1-7 reserved, MUST be 0 in v1. bit0 = multi-contract.
        if flags & !0x01 != 0 {
            return Err(Error::Decode(format!(
                "unknown commitment flags 0x{flags:02x}"
            )));
        }
        if payload[39] != 0x00 {
            return Err(Error::Decode("reserved commitment byte is not 0".into()));
        }
        Ok(Self {
            version: 1,
            kind,
            root,
            flags,
        })
    }

    pub fn single(op: &Operation) -> Result<Self, Error> {
        Ok(Self {
            version: 1,
            kind: CommitmentKind::Single,
            root: op.commitment_leaf()?,
            flags: 0,
        })
    }

    pub fn merkle(ops: &[Operation]) -> Result<Self, Error> {
        if ops.len() < 2 {
            return Err(Error::Encode("kind 0x02 requires 2..n operations".into()));
        }
        let mut leaves = Vec::with_capacity(ops.len());
        let mut contracts: Vec<[u8; 32]> = Vec::new();
        for op in ops {
            leaves.push(op.commitment_leaf()?);
            if !contracts.iter().any(|c| *c == op.contract_id.0) {
                contracts.push(op.contract_id.0);
            }
        }
        let flags = if contracts.len() > 1 { 0x01 } else { 0 };
        Ok(Self {
            version: 1,
            kind: CommitmentKind::Merkle,
            root: merkle_root(leaves),
            flags,
        })
    }

    /// T6 / G5: does this commitment cover `op` given the full batch in this L1 tx?
    pub fn covers(&self, op: &Operation, batch: &[Operation]) -> Result<bool, Error> {
        match self.kind {
            CommitmentKind::Single => {
                if batch.len() != 1 {
                    return Ok(false);
                }
                Ok(self.root == op.commitment_leaf()? && op.encode()? == batch[0].encode()?)
            }
            CommitmentKind::Merkle => {
                if batch.len() < 2 {
                    return Ok(false);
                }
                if !batch.iter().any(|o| o.op_hash().ok() == op.op_hash().ok()) {
                    return Ok(false);
                }
                let mut leaves = Vec::new();
                for o in batch {
                    leaves.push(o.commitment_leaf()?);
                }
                Ok(self.root == merkle_root(leaves))
            }
        }
    }
}

/// Bitcoin-style merkle of already-tagged op hashes, sorted, duplicate last on odd count.
pub fn merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    leaves.sort();
    if leaves.len() == 1 {
        return leaves[0];
    }
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            if let Some(last) = leaves.last().copied() {
                leaves.push(last);
            }
        }
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            let mut cat = [0u8; 64];
            cat[..32].copy_from_slice(&pair[0]);
            cat[32..].copy_from_slice(&pair[1]);
            next.push(sha256d(&cat));
        }
        leaves = next;
    }
    leaves[0]
}
