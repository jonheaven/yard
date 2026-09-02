use crate::hash::Reader;
use crate::l1::Transaction;
use crate::operation::Operation;
use crate::Error;
use serde::{Deserialize, Serialize};

pub const CONS_MAGIC: &[u8; 8] = b"YARDCONS";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Internal-order txid of the committing tx.
    pub txid: [u8; 32],
    pub blockhash: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consignment {
    pub version: u8,
    pub ops: Vec<Operation>,
    pub txs: Vec<Transaction>,
    pub proofs: Vec<MerkleProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConsignmentJson {
    v: u8,
    ops: Vec<String>,
    txs: Vec<String>,
    #[serde(default)]
    proofs: Vec<ProofJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProofJson {
    txid: String,
    blockhash: String,
    path: Vec<String>,
    index: u32,
}

impl Consignment {
    pub fn new(ops: Vec<Operation>, txs: Vec<Transaction>) -> Self {
        Self {
            version: 1,
            ops,
            txs,
            proofs: Vec::new(),
        }
    }

    pub fn encode_binary(&self) -> Result<Vec<u8>, Error> {
        if self.ops.len() > u32::MAX as usize || self.txs.len() > u32::MAX as usize {
            return Err(Error::Encode("consignment too large".into()));
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(CONS_MAGIC);
        buf.push(self.version);
        buf.extend_from_slice(&(self.ops.len() as u32).to_le_bytes());
        for op in &self.ops {
            let bytes = op.encode()?;
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&bytes);
        }
        buf.extend_from_slice(&(self.txs.len() as u32).to_le_bytes());
        for tx in &self.txs {
            let bytes = tx.encode();
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&bytes);
        }
        buf.extend_from_slice(&(self.proofs.len() as u32).to_le_bytes());
        for p in &self.proofs {
            buf.extend_from_slice(&p.txid);
            buf.extend_from_slice(&p.blockhash);
            buf.extend_from_slice(&(p.path.len() as u32).to_le_bytes());
            for h in &p.path {
                buf.extend_from_slice(h);
            }
            buf.extend_from_slice(&p.index.to_le_bytes());
        }
        Ok(buf)
    }

    pub fn decode_binary(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let magic = r.bytes(8)?;
        if magic != CONS_MAGIC {
            return Err(Error::Consignment("magic is not YARDCONS".into()));
        }
        let version = r.u8()?;
        if version != 1 {
            return Err(Error::Consignment(format!("version {version} != 1")));
        }
        let n_ops = r.u32()? as usize;
        let mut ops = Vec::with_capacity(n_ops);
        for _ in 0..n_ops {
            let n = r.u32()? as usize;
            ops.push(Operation::decode(r.bytes(n)?)?);
        }
        let n_txs = r.u32()? as usize;
        let mut txs = Vec::with_capacity(n_txs);
        for _ in 0..n_txs {
            let n = r.u32()? as usize;
            txs.push(Transaction::decode(r.bytes(n)?)?);
        }
        let n_proofs = r.u32()? as usize;
        let mut proofs = Vec::with_capacity(n_proofs);
        for _ in 0..n_proofs {
            let txid = r.array()?;
            let blockhash = r.array()?;
            let n_path = r.u32()? as usize;
            let mut path = Vec::with_capacity(n_path);
            for _ in 0..n_path {
                path.push(r.array()?);
            }
            let index = r.u32()?;
            proofs.push(MerkleProof {
                txid,
                blockhash,
                path,
                index,
            });
        }
        r.finish()?;
        Ok(Self {
            version,
            ops,
            txs,
            proofs,
        })
    }

    pub fn encode_json(&self) -> Result<Vec<u8>, Error> {
        let j = ConsignmentJson {
            v: self.version,
            ops: self
                .ops
                .iter()
                .map(|o| o.encode().map(hex::encode))
                .collect::<Result<_, _>>()?,
            txs: self.txs.iter().map(|t| hex::encode(t.encode())).collect(),
            proofs: self
                .proofs
                .iter()
                .map(|p| ProofJson {
                    txid: hex::encode(p.txid),
                    blockhash: hex::encode(p.blockhash),
                    path: p.path.iter().map(hex::encode).collect(),
                    index: p.index,
                })
                .collect(),
        };
        serde_json::to_vec_pretty(&j).map_err(|e| Error::Consignment(e.to_string()))
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, Error> {
        let j: ConsignmentJson =
            serde_json::from_slice(bytes).map_err(|e| Error::Consignment(e.to_string()))?;
        if j.v != 1 {
            return Err(Error::Consignment(format!("json version {} != 1", j.v)));
        }
        let mut ops = Vec::new();
        for h in j.ops {
            let b = hex::decode(h).map_err(|e| Error::Consignment(e.to_string()))?;
            ops.push(Operation::decode(&b)?);
        }
        let mut txs = Vec::new();
        for h in j.txs {
            let b = hex::decode(h).map_err(|e| Error::Consignment(e.to_string()))?;
            txs.push(Transaction::decode(&b)?);
        }
        let mut proofs = Vec::new();
        for p in j.proofs {
            proofs.push(MerkleProof {
                txid: hex32(&p.txid)?,
                blockhash: hex32(&p.blockhash)?,
                path: p.path.iter().map(|s| hex32(s)).collect::<Result<_, _>>()?,
                index: p.index,
            });
        }
        Ok(Self {
            version: 1,
            ops,
            txs,
            proofs,
        })
    }

    /// Auto-detect binary (`YARDCONS`) vs JSON (`{`).
    pub fn decode_any(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.starts_with(CONS_MAGIC) {
            Self::decode_binary(bytes)
        } else {
            Self::decode_json(bytes)
        }
    }
}

fn hex32(s: &str) -> Result<[u8; 32], Error> {
    let b = hex::decode(s).map_err(|e| Error::Consignment(e.to_string()))?;
    if b.len() != 32 {
        return Err(Error::Consignment("expected 32 bytes".into()));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}
