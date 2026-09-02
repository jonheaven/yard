use crate::address::hash160;
use crate::fee::{estimate_legacy_size, fee_for_size, is_soft_dust};
use crate::Error;
use secp256k1::{Message, PublicKey, SecretKey, SECP256K1};
use yard_core::{
    opreturn_script, p2pkh_script, sha256d, Commitment, Outpoint, Transaction, TxIn, TxOut,
    SOFT_DUST_KOINU,
};

pub const SIGHASH_ALL: u8 = 0x01;

#[derive(Clone, Debug)]
pub struct Spendable {
    pub prevout: Outpoint,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub secret: SecretKey,
}

#[derive(Clone, Debug)]
pub struct SealOutput {
    pub value: u64,
    pub pubkey: [u8; 33],
}

/// Ordinary P2PKH payment that is not a YARD seal (treasury raise, sell refund).
#[derive(Clone, Debug)]
pub struct PayOutput {
    pub value: u64,
    pub pkh: [u8; 20],
}

/// Build a standard YARD L1 tx:
///   outputs[0] = OP_RETURN commitment (value 0)
///   outputs[1..k] = seal P2PKH, each >= 0.01 DOGE
///   last = change P2PKH if above soft dust
pub fn build_yard_tx(
    inputs: &[Spendable],
    seals: &[SealOutput],
    change_pkh: Option<[u8; 20]>,
    commitment: &Commitment,
) -> Result<Transaction, Error> {
    build_yard_tx_with_pays(inputs, seals, &[], change_pkh, commitment)
}

/// Same as `build_yard_tx`, plus extra P2PKH pays after the seals.
/// Seal vouts stay 1..k so operation `this_tx(n)` indexing is unchanged.
/// Empty seals are allowed (full burn): OP_RETURN + change.
pub fn build_yard_tx_with_pays(
    inputs: &[Spendable],
    seals: &[SealOutput],
    pays: &[PayOutput],
    change_pkh: Option<[u8; 20]>,
    commitment: &Commitment,
) -> Result<Transaction, Error> {
    if inputs.is_empty() {
        return Err(Error::Tx("no inputs".into()));
    }
    for s in seals {
        if s.value < SOFT_DUST_KOINU {
            return Err(Error::Tx("seal output below 0.01 DOGE soft dust".into()));
        }
    }
    let in_sum: u64 = inputs.iter().map(|i| i.value).sum();
    let seal_sum: u64 = seals.iter().map(|s| s.value).sum();
    let pay_sum: u64 = pays.iter().map(|p| p.value).sum();
    let committed = seal_sum.saturating_add(pay_sum);
    if in_sum <= committed {
        return Err(Error::Tx("inputs cannot cover seals + payments".into()));
    }

    let payload = commitment.encode();
    let mut change = true;
    let mut tx = assemble(
        inputs,
        seals,
        pays,
        change_pkh.filter(|_| change),
        &payload,
        0,
    )?;
    // Iterate until the started-kilobyte fee bracket is stable.
    for _ in 0..8 {
        let size = tx.encode().len().max(estimate_legacy_size(
            inputs.len(),
            seals.len() + pays.len() + usize::from(change),
            payload.len(),
        ));
        let fee = fee_for_size(size);
        if in_sum < committed + fee {
            return Err(Error::Tx(format!(
                "insufficient funds: in={in_sum} committed={committed} fee={fee}"
            )));
        }
        let change_val = in_sum - committed - fee;
        change = change_val >= SOFT_DUST_KOINU && change_pkh.is_some();
        if change && is_soft_dust(change_val) {
            change = false;
        }
        let actual_change = if change { change_val } else { 0 };
        tx = assemble(
            inputs,
            seals,
            pays,
            if change { change_pkh } else { None },
            &payload,
            actual_change,
        )?;
        sign_p2pkh_inputs(&mut tx, inputs)?;
        let real_fee = fee_for_size(tx.encode().len());
        let leftover = in_sum - committed - if change { actual_change } else { 0 };
        if leftover >= real_fee {
            return Ok(tx);
        }
    }
    Err(Error::Tx("could not stabilize fee".into()))
}

fn assemble(
    inputs: &[Spendable],
    seals: &[SealOutput],
    pays: &[PayOutput],
    change_pkh: Option<[u8; 20]>,
    payload: &[u8],
    change_value: u64,
) -> Result<Transaction, Error> {
    let mut vin = Vec::new();
    for i in inputs {
        vin.push(TxIn {
            prevout: i.prevout,
            script_sig: Vec::new(),
            sequence: 0xffffffff,
        });
    }
    let mut vout = Vec::new();
    vout.push(TxOut {
        value: 0,
        script_pubkey: opreturn_script(payload)?,
    });
    for s in seals {
        let pkh = hash160(&s.pubkey);
        vout.push(TxOut {
            value: s.value,
            script_pubkey: p2pkh_script(&pkh),
        });
    }
    for p in pays {
        vout.push(TxOut {
            value: p.value,
            script_pubkey: p2pkh_script(&p.pkh),
        });
    }
    if let Some(pkh) = change_pkh {
        vout.push(TxOut {
            value: change_value,
            script_pubkey: p2pkh_script(&pkh),
        });
    }
    Ok(Transaction {
        version: 1,
        vin,
        vout,
        lock_time: 0,
    })
}

fn sign_p2pkh_inputs(tx: &mut Transaction, inputs: &[Spendable]) -> Result<(), Error> {
    for (idx, spend) in inputs.iter().enumerate() {
        let hash = signature_hash(tx, idx, &spend.script_pubkey, SIGHASH_ALL)?;
        let msg = Message::from_digest(hash);
        let sig = SECP256K1.sign_ecdsa(&msg, &spend.secret);
        let mut der = sig.serialize_der().to_vec();
        der.push(SIGHASH_ALL);
        let pk = PublicKey::from_secret_key(SECP256K1, &spend.secret).serialize();
        let mut script_sig = Vec::new();
        script_sig.push(der.len() as u8);
        script_sig.extend_from_slice(&der);
        script_sig.push(pk.len() as u8);
        script_sig.extend_from_slice(&pk);
        tx.vin[idx].script_sig = script_sig;
    }
    Ok(())
}

/// Legacy SIGHASH_ALL: empty all scriptSigs, put `script_code` in the input
/// being signed, serialize, append sighash type as u32 LE, SHA256d.
pub fn signature_hash(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    sighash_type: u8,
) -> Result<[u8; 32], Error> {
    if input_index >= tx.vin.len() {
        return Err(Error::Tx("input_index out of range".into()));
    }
    let mut tmp = tx.clone();
    for (i, vin) in tmp.vin.iter_mut().enumerate() {
        vin.script_sig = if i == input_index {
            script_code.to_vec()
        } else {
            Vec::new()
        };
    }
    let mut encoded = tmp.encode();
    encoded.extend_from_slice(&(sighash_type as u32).to_le_bytes());
    Ok(sha256d(&encoded))
}

/// Dummy tx used to freeze a hex snapshot (fixed test scalar, fixed prevout).
/// Shape: one P2PKH input, OP_RETURN, two P2PKH seal outs. No change.
pub fn dummy_snapshot_tx() -> Result<Transaction, Error> {
    use yard_core::{
        compressed_pubkey, test_secret, Amount, ContractId, OpOutput, OpType, Operation,
    };
    let sk = test_secret();
    let pk = compressed_pubkey(&sk);
    let op = Operation {
        op_version: 1,
        contract_id: ContractId::zeros(),
        op_type: OpType::Genesis,
        inputs: vec![],
        outputs: vec![OpOutput {
            seal: Outpoint::this_tx(1),
            amount: Amount(1),
            pubkey: pk,
        }],
        meta: b"{}".to_vec(),
        sigs: vec![[0u8; 64]],
    };
    let cm = Commitment::single(&op)?;
    let prev_txid = sha256d(b"yard-dummy-prevout");
    let script = p2pkh_script(&hash160(&pk));
    // 0.10 DOGE in, two 0.05 DOGE seals, fee takes the remainder of the
    // started-kilobyte bracket so no change output is produced.
    let inputs = vec![Spendable {
        prevout: Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        value: 11_000_000,
        script_pubkey: script,
        secret: sk,
    }];
    let seals = vec![
        SealOutput {
            value: 5_000_000,
            pubkey: pk,
        },
        SealOutput {
            value: 5_000_000,
            pubkey: pk,
        },
    ];
    build_yard_tx(&inputs, &seals, None, &cm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_dummy_tx_snapshot() {
        let tx = dummy_snapshot_tx().unwrap();
        assert_eq!(tx.vin.len(), 1);
        assert_eq!(tx.vout.len(), 3); // OP_RETURN + two P2PKH seals
        assert_eq!(tx.vout[0].value, 0);
        let payload = yard_core::parse_opreturn_payload(&tx.vout[0].script_pubkey)
            .unwrap()
            .unwrap();
        assert_eq!(payload.len(), 40);
        assert_eq!(&payload[0..4], b"YARD");
        let hex = hex::encode(tx.encode());
        let expected = include_str!("../../../tests/vectors/dummy_tx.hex").trim();
        assert_eq!(hex, expected);
    }
}
