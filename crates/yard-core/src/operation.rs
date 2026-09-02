use crate::hash::{tagged_sha256d, Reader, TAG_OP, TAG_SIGHASH};
use crate::outpoint::{ContractId, Outpoint};
use crate::sig::{sign_compact, verify_compact};
use crate::{sha256d, Amount, Error, META_MAX};
use secp256k1::SecretKey;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OpType {
    Genesis = 0x00,
    Transfer = 0x01,
    Burn = 0x02,
    LaunchBuy = 0x03,
    LaunchSell = 0x04,
}

impl OpType {
    pub fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0x00 => Ok(Self::Genesis),
            0x01 => Ok(Self::Transfer),
            0x02 => Ok(Self::Burn),
            0x03 => Ok(Self::LaunchBuy),
            0x04 => Ok(Self::LaunchSell),
            _ => Err(Error::T8),
        }
    }

    /// T8: Phase 0 allows genesis, transfer, burn only.
    pub fn allowed_phase0(self) -> bool {
        matches!(self, Self::Genesis | Self::Transfer | Self::Burn)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpInput {
    pub prev_op_hash: [u8; 32],
    pub prev_seal: Outpoint,
    pub amount: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpOutput {
    pub seal: Outpoint,
    pub amount: Amount,
    pub pubkey: [u8; 33],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub op_version: u8,
    pub contract_id: ContractId,
    pub op_type: OpType,
    pub inputs: Vec<OpInput>,
    pub outputs: Vec<OpOutput>,
    pub meta: Vec<u8>,
    pub sigs: Vec<[u8; 64]>,
}

impl Operation {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.encode_inner(false)
    }

    /// Canonical bytes with signature fields zeroed (sighash).
    pub fn encode_for_sighash(&self) -> Result<Vec<u8>, Error> {
        self.encode_inner(true)
    }

    fn encode_inner(&self, sighash: bool) -> Result<Vec<u8>, Error> {
        if self.inputs.len() > u16::MAX as usize {
            return Err(Error::Encode("input_count exceeds u16".into()));
        }
        if self.outputs.len() > u16::MAX as usize {
            return Err(Error::Encode("output_count exceeds u16".into()));
        }
        if self.meta.len() > META_MAX {
            return Err(Error::Encode("meta exceeds 512 bytes".into()));
        }
        if self.sigs.len() > 255 {
            return Err(Error::Encode("sig_count exceeds u8".into()));
        }
        let mut buf = Vec::new();
        buf.push(self.op_version);
        buf.extend_from_slice(&self.contract_id.0);
        buf.push(self.op_type as u8);
        buf.extend_from_slice(&(self.inputs.len() as u16).to_le_bytes());
        for i in &self.inputs {
            buf.extend_from_slice(&i.prev_op_hash);
            i.prev_seal.encode(&mut buf);
            buf.extend_from_slice(&i.amount.to_le_bytes());
        }
        buf.extend_from_slice(&(self.outputs.len() as u16).to_le_bytes());
        for o in &self.outputs {
            o.seal.encode(&mut buf);
            buf.extend_from_slice(&o.amount.to_le_bytes());
            buf.extend_from_slice(&o.pubkey);
        }
        buf.extend_from_slice(&(self.meta.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.meta);
        buf.push(self.sigs.len() as u8);
        for sig in &self.sigs {
            if sighash {
                buf.extend_from_slice(&[0u8; 64]);
            } else {
                buf.extend_from_slice(sig);
            }
        }
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let op_version = r.u8()?;
        if op_version != 1 {
            return Err(Error::Decode(format!("op_version {op_version} != 1")));
        }
        let contract_id = ContractId(r.array()?);
        let op_type = OpType::from_u8(r.u8()?)?;
        let input_count = r.u16()? as usize;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            inputs.push(OpInput {
                prev_op_hash: r.array()?,
                prev_seal: Outpoint::decode(&mut r)?,
                amount: Amount(r.u128()?),
            });
        }
        let output_count = r.u16()? as usize;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let seal = Outpoint::decode(&mut r)?;
            let amount = Amount(r.u128()?);
            let pubkey = r.array()?;
            if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
                return Err(Error::Decode("pubkey is not compressed".into()));
            }
            outputs.push(OpOutput {
                seal,
                amount,
                pubkey,
            });
        }
        let meta_len = r.u16()? as usize;
        if meta_len > META_MAX {
            return Err(Error::Decode("meta_len exceeds 512".into()));
        }
        let meta = r.bytes(meta_len)?.to_vec();
        let sig_count = r.u8()? as usize;
        let mut sigs = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            sigs.push(r.array()?);
        }
        r.finish()?;
        Ok(Self {
            op_version,
            contract_id,
            op_type,
            inputs,
            outputs,
            meta,
            sigs,
        })
    }

    pub fn sighash(&self) -> Result<[u8; 32], Error> {
        Ok(tagged_sha256d(TAG_SIGHASH, &self.encode_for_sighash()?))
    }

    /// Sign slot `index` with `sk`. Genesis uses index 0 and sig_count = 1.
    pub fn sign(&mut self, index: usize, sk: &SecretKey) -> Result<(), Error> {
        if index >= self.sigs.len() {
            return Err(Error::Encode("sig index out of range".into()));
        }
        let h = self.sighash()?;
        self.sigs[index] = sign_compact(&h, sk)?;
        Ok(())
    }

    pub fn verify_sig(&self, index: usize, pk33: &[u8; 33]) -> Result<(), Error> {
        let sig = self.sigs.get(index).ok_or(Error::T5)?;
        verify_compact(&self.sighash()?, sig, pk33)
    }

    /// SHA256d of canonical (signed) bytes. Genesis ContractId is this hash.
    pub fn op_hash(&self) -> Result<[u8; 32], Error> {
        Ok(sha256d(&self.encode()?))
    }

    /// Leaf used in the OP_RETURN commitment: SHA256d("yard/op/v1" || op_bytes).
    pub fn commitment_leaf(&self) -> Result<[u8; 32], Error> {
        Ok(tagged_sha256d(TAG_OP, &self.encode()?))
    }

    /// G2: ContractId := SHA256d(genesis bytes including sig).
    pub fn genesis_contract_id(&self) -> Result<ContractId, Error> {
        if self.op_type != OpType::Genesis {
            return Err(Error::Decode("not a genesis operation".into()));
        }
        Ok(ContractId(self.op_hash()?))
    }

    pub fn input_sum(&self) -> Result<Amount, Error> {
        self.inputs
            .iter()
            .try_fold(Amount::ZERO, |a, i| a.checked_add(i.amount))
            .ok_or_else(|| Error::Decode("input amount overflow".into()))
    }

    pub fn output_sum(&self) -> Result<Amount, Error> {
        self.outputs
            .iter()
            .try_fold(Amount::ZERO, |a, o| a.checked_add(o.amount))
            .ok_or_else(|| Error::Decode("output amount overflow".into()))
    }

    pub fn expected_sig_count(&self) -> usize {
        match self.op_type {
            OpType::Genesis => 1,
            _ => self.inputs.len(),
        }
    }
}
