use crate::commitment::Commitment;
use crate::hash::{read_compact_size, write_compact_size, Reader};
use crate::outpoint::Outpoint;
use crate::{sha256d, Error, SOFT_DUST_KOINU};

/// Pre-SegWit Dogecoin transaction. No witness. Versioned like Core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: Outpoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl Transaction {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_le_bytes());
        write_compact_size(&mut buf, self.vin.len() as u64);
        for i in &self.vin {
            i.prevout.encode(&mut buf);
            write_compact_size(&mut buf, i.script_sig.len() as u64);
            buf.extend_from_slice(&i.script_sig);
            buf.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_compact_size(&mut buf, self.vout.len() as u64);
        for o in &self.vout {
            buf.extend_from_slice(&o.value.to_le_bytes());
            write_compact_size(&mut buf, o.script_pubkey.len() as u64);
            buf.extend_from_slice(&o.script_pubkey);
        }
        buf.extend_from_slice(&self.lock_time.to_le_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let version = {
            let b = r.bytes(4)?;
            i32::from_le_bytes([b[0], b[1], b[2], b[3]])
        };
        let n_in = read_compact_size(&mut r)? as usize;
        let mut vin = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let prevout = Outpoint::decode(&mut r)?;
            let slen = read_compact_size(&mut r)? as usize;
            let script_sig = r.bytes(slen)?.to_vec();
            let sequence = r.u32()?;
            vin.push(TxIn {
                prevout,
                script_sig,
                sequence,
            });
        }
        let n_out = read_compact_size(&mut r)? as usize;
        let mut vout = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            let vb = r.bytes(8)?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(vb);
            let value = u64::from_le_bytes(arr);
            let slen = read_compact_size(&mut r)? as usize;
            let script_pubkey = r.bytes(slen)?.to_vec();
            vout.push(TxOut {
                value,
                script_pubkey,
            });
        }
        let lock_time = r.u32()?;
        r.finish()?;
        Ok(Self {
            version,
            vin,
            vout,
            lock_time,
        })
    }

    /// Internal-order txid (SHA256d of the serialized tx).
    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.encode())
    }

    pub fn txid_rpc_hex(&self) -> String {
        crate::outpoint::rpc_hex(&self.txid())
    }

    /// Parse the first OP_RETURN that looks like a YARD v1 commitment.
    pub fn yard_commitment(&self) -> Result<Option<Commitment>, Error> {
        for o in &self.vout {
            if let Some(payload) = parse_opreturn_payload(&o.script_pubkey)? {
                if payload.starts_with(&crate::MAGIC_BYTES) {
                    return Ok(Some(Commitment::decode(&payload)?));
                }
            }
        }
        Ok(None)
    }

    pub fn spends(&self, op: &Outpoint) -> bool {
        self.vin.iter().any(|i| i.prevout == *op)
    }

    pub fn output(&self, vout: u32) -> Option<&TxOut> {
        self.vout.get(vout as usize)
    }

    pub fn seal_value_ok(&self, vout: u32) -> bool {
        self.output(vout)
            .map(|o| o.value >= SOFT_DUST_KOINU)
            .unwrap_or(false)
    }
}

/// OP_RETURN + push of `payload`. Payload must be <= 80 bytes (v1 uses 40).
pub fn opreturn_script(payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > 80 {
        return Err(Error::L1("OP_RETURN payload exceeds 80-byte floor".into()));
    }
    if payload.len() > 75 {
        // PUSHDATA1. v1 never needs this (40 bytes).
        let mut s = Vec::with_capacity(3 + payload.len());
        s.push(0x6a);
        s.push(0x4c);
        s.push(payload.len() as u8);
        s.extend_from_slice(payload);
        return Ok(s);
    }
    let mut s = Vec::with_capacity(2 + payload.len());
    s.push(0x6a);
    s.push(payload.len() as u8);
    s.extend_from_slice(payload);
    Ok(s)
}

/// Extract the first pushed payload of an OP_RETURN script.
/// Rejects scripts that are not a single OP_RETURN + a single push.
pub fn parse_opreturn_payload(script: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    if script.is_empty() || script[0] != 0x6a {
        return Ok(None);
    }
    if script.len() == 1 {
        return Ok(Some(Vec::new()));
    }
    let (payload, rest) = read_push(&script[1..])?;
    if !rest.is_empty() {
        return Err(Error::L1(
            "OP_RETURN script has extra opcodes after the data push".into(),
        ));
    }
    Ok(Some(payload))
}

fn read_push(script: &[u8]) -> Result<(Vec<u8>, &[u8]), Error> {
    if script.is_empty() {
        return Err(Error::L1("truncated script push".into()));
    }
    let op = script[0];
    match op {
        0x01..=0x4b => {
            let n = op as usize;
            if script.len() < 1 + n {
                return Err(Error::L1("truncated script push".into()));
            }
            Ok((script[1..1 + n].to_vec(), &script[1 + n..]))
        }
        0x4c => {
            if script.len() < 2 {
                return Err(Error::L1("truncated PUSHDATA1".into()));
            }
            let n = script[1] as usize;
            if script.len() < 2 + n {
                return Err(Error::L1("truncated PUSHDATA1 payload".into()));
            }
            Ok((script[2..2 + n].to_vec(), &script[2 + n..]))
        }
        0x4d => {
            if script.len() < 3 {
                return Err(Error::L1("truncated PUSHDATA2".into()));
            }
            let n = u16::from_le_bytes([script[1], script[2]]) as usize;
            if script.len() < 3 + n {
                return Err(Error::L1("truncated PUSHDATA2 payload".into()));
            }
            Ok((script[3..3 + n].to_vec(), &script[3 + n..]))
        }
        _ => Err(Error::L1(format!(
            "unsupported script push opcode 0x{op:02x}"
        ))),
    }
}

pub fn p2pkh_script(pkh: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(0x76);
    s.push(0xa9);
    s.push(0x14);
    s.extend_from_slice(pkh);
    s.push(0x88);
    s.push(0xac);
    s
}

pub fn is_p2pkh(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[3..23]);
        Some(h)
    } else {
        None
    }
}
