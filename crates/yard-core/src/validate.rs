use crate::consignment::Consignment;
use crate::l1::Transaction;
use crate::meta::GenesisMeta;
use crate::operation::{OpType, Operation};
use crate::outpoint::{ContractId, Outpoint};
use crate::{Amount, Error, SOFT_DUST_KOINU};
use std::collections::HashSet;

/// An operation that has already passed local validation, bound to its L1 txid
/// (internal byte order).
#[derive(Clone, Debug)]
pub struct AcceptedOp {
    pub op: Operation,
    pub l1_txid: [u8; 32],
    pub contract_id: ContractId,
}

/// Validate a single operation against previous accepted ops and the committing L1 tx.
///
/// `batch` is every YARD operation committed in `l1_tx` (just `[op]` for kind 0x01).
/// G6 (confirmations) is applied by the caller with a Dogecoin node.
pub fn validate_operation(
    op: &Operation,
    prev: &[AcceptedOp],
    l1_tx: &Transaction,
    batch: &[Operation],
) -> Result<(), Error> {
    if op.op_version != 1 {
        return Err(Error::Decode("op_version != 1".into()));
    }
    // T8
    if !op.op_type.allowed_phase0() {
        return Err(Error::T8);
    }
    if op.sigs.len() != op.expected_sig_count() {
        return Err(Error::Decode(
            "sig_count must equal input_count except genesis=1".into(),
        ));
    }

    let l1_txid = l1_tx.txid();
    let cm = l1_tx
        .yard_commitment()?
        .ok_or(if op.op_type == OpType::Genesis {
            Error::G5
        } else {
            Error::T6
        })?;
    if !cm.covers(op, batch)? {
        return Err(if op.op_type == OpType::Genesis {
            Error::G5
        } else {
            Error::T6
        });
    }

    match op.op_type {
        OpType::Genesis => validate_genesis(op, l1_tx, &l1_txid)?,
        OpType::Transfer | OpType::Burn => validate_spend(op, prev, l1_tx, &l1_txid)?,
        OpType::LaunchBuy | OpType::LaunchSell => return Err(Error::T8),
    }
    Ok(())
}

/// G1–G5.
fn validate_genesis(op: &Operation, l1_tx: &Transaction, l1_txid: &[u8; 32]) -> Result<(), Error> {
    if !op.contract_id.is_zeros() {
        return Err(Error::Decode(
            "genesis contract_id field must be 32 zero bytes".into(),
        ));
    }
    if op.inputs.is_empty() == false {
        return Err(Error::Decode("genesis must have zero inputs".into()));
    }
    if op.outputs.is_empty() {
        return Err(Error::Decode(
            "genesis must have at least one output".into(),
        ));
    }
    if op.sigs.len() != 1 {
        return Err(Error::G1);
    }
    // G1: signature valid under the genesis pubkey (first output).
    op.verify_sig(0, &op.outputs[0].pubkey)
        .map_err(|_| Error::G1)?;

    let meta = GenesisMeta::from_bytes(&op.meta)?;
    let max = meta.max_amount()?;
    let sum = op.output_sum()?;
    // G3
    if sum != max {
        return Err(Error::G3);
    }

    let mut seen = HashSet::new();
    for o in &op.outputs {
        // G4 + T4 dust on genesis outputs too (seals must relay).
        check_output_seal(o.seal, l1_tx, l1_txid, Error::G4)?;
        let resolved = o.seal.resolved(l1_txid);
        if !seen.insert(resolved) {
            return Err(Error::T7);
        }
    }
    Ok(())
}

/// T1–T8 for transfer and burn.
fn validate_spend(
    op: &Operation,
    prev: &[AcceptedOp],
    l1_tx: &Transaction,
    l1_txid: &[u8; 32],
) -> Result<(), Error> {
    if op.inputs.is_empty() {
        return Err(Error::T1);
    }
    if !op.contract_id.is_zeros() {
        if let Some(g) = prev.first() {
            if op.contract_id != g.contract_id {
                return Err(Error::Decode("contract_id does not match genesis".into()));
            }
        }
    }

    let in_sum = op.input_sum()?;
    let out_sum = op.output_sum()?;
    match op.op_type {
        OpType::Transfer => {
            // T2: burned = 0
            if in_sum != out_sum {
                return Err(Error::T2);
            }
        }
        OpType::Burn => {
            // T2: burned = in - out, must be strictly positive
            if out_sum.0 > in_sum.0 {
                return Err(Error::T2);
            }
            if out_sum == in_sum {
                return Err(Error::T2);
            }
        }
        _ => return Err(Error::T8),
    }

    let mut closed = HashSet::new();
    for (i, inp) in op.inputs.iter().enumerate() {
        // T7: no seal closed twice in this op.
        if !closed.insert(inp.prev_seal) {
            return Err(Error::T7);
        }
        // T3: spent by this L1 tx.
        if !l1_tx.spends(&inp.prev_seal) {
            return Err(Error::T3);
        }
        // T1 + T5: previous accepted op assigned this seal + pubkey.
        let (prev_op, prev_txid) = find_prev(prev, &inp.prev_op_hash)?;
        let assigned = find_assigned(prev_op, prev_txid, &inp.prev_seal, inp.amount)?;
        op.verify_sig(i, &assigned).map_err(|_| Error::T5)?;
    }

    let mut opened = HashSet::new();
    for o in &op.outputs {
        check_output_seal(o.seal, l1_tx, l1_txid, Error::T4)?;
        let resolved = o.seal.resolved(l1_txid);
        if !opened.insert(resolved) {
            return Err(Error::T7);
        }
    }
    Ok(())
}

fn check_output_seal(
    seal: Outpoint,
    l1_tx: &Transaction,
    l1_txid: &[u8; 32],
    mismatch: Error,
) -> Result<(), Error> {
    if !seal.is_output_of(l1_txid) {
        return Err(mismatch);
    }
    let out = l1_tx.output(seal.vout).ok_or(mismatch)?;
    // T4 dust (also applied to genesis via G4 helper)
    if out.value < SOFT_DUST_KOINU {
        return Err(Error::T4);
    }
    Ok(())
}

fn find_prev<'a>(
    prev: &'a [AcceptedOp],
    hash: &[u8; 32],
) -> Result<(&'a Operation, [u8; 32]), Error> {
    for a in prev {
        if a.op.op_hash()? == *hash {
            return Ok((&a.op, a.l1_txid));
        }
    }
    Err(Error::T1)
}

fn find_assigned(
    prev_op: &Operation,
    prev_txid: [u8; 32],
    seal: &Outpoint,
    amount: Amount,
) -> Result<[u8; 33], Error> {
    for o in &prev_op.outputs {
        let resolved = o.seal.resolved(&prev_txid);
        if resolved == *seal {
            if o.amount != amount {
                return Err(Error::T1);
            }
            return Ok(o.pubkey);
        }
    }
    Err(Error::T1)
}

/// Walk a consignment from genesis to tip. Does not apply G6.
pub fn validate_consignment(c: &Consignment) -> Result<Vec<AcceptedOp>, Error> {
    if c.ops.is_empty() {
        return Err(Error::Consignment("no operations".into()));
    }
    if c.ops[0].op_type != OpType::Genesis {
        return Err(Error::Consignment("first operation must be genesis".into()));
    }
    if c.txs.is_empty() {
        return Err(Error::Consignment(
            "Phase 0 consignments must include full L1 txs".into(),
        ));
    }

    let mut accepted: Vec<AcceptedOp> = Vec::new();
    let mut closed_global: HashSet<Outpoint> = HashSet::new();

    for op in &c.ops {
        let batch_and_tx = find_committing_tx(op, c)?;
        let (tx, batch) = batch_and_tx;
        validate_operation(op, &accepted, tx, &batch)?;

        let l1_txid = tx.txid();
        for inp in &op.inputs {
            if !closed_global.insert(inp.prev_seal) {
                return Err(Error::T7);
            }
        }

        let contract_id = if op.op_type == OpType::Genesis {
            // G2: receiver recomputes ContractId from genesis bytes.
            op.genesis_contract_id()?
        } else {
            accepted.first().map(|a| a.contract_id).ok_or(Error::T1)?
        };

        accepted.push(AcceptedOp {
            op: op.clone(),
            l1_txid,
            contract_id,
        });
    }
    Ok(accepted)
}

fn find_committing_tx<'a>(
    op: &Operation,
    c: &'a Consignment,
) -> Result<(&'a Transaction, Vec<Operation>), Error> {
    let leaf = op.commitment_leaf()?;
    for tx in &c.txs {
        let Some(cm) = tx.yard_commitment()? else {
            continue;
        };
        match cm.kind {
            crate::commitment::CommitmentKind::Single => {
                if cm.root == leaf {
                    return Ok((tx, vec![op.clone()]));
                }
            }
            crate::commitment::CommitmentKind::Merkle => {
                let bound: Vec<Operation> = c
                    .ops
                    .iter()
                    .filter(|o| op_binds_graph(o, tx))
                    .cloned()
                    .collect();
                if bound.len() >= 2 && cm.covers(op, &bound).unwrap_or(false) {
                    return Ok((tx, bound));
                }
            }
        }
    }
    if op.op_type == OpType::Genesis {
        Err(Error::G5)
    } else {
        Err(Error::T6)
    }
}

fn op_binds_graph(op: &Operation, tx: &Transaction) -> bool {
    let txid = tx.txid();
    op.inputs.iter().all(|i| tx.spends(&i.prev_seal))
        && op
            .outputs
            .iter()
            .all(|o| o.seal.is_output_of(&txid) && tx.output(o.seal.vout).is_some())
}

/// Current notes (unspent seals) at the tip of a validated consignment.
pub fn open_notes(accepted: &[AcceptedOp]) -> Vec<(Outpoint, Amount, [u8; 33], ContractId)> {
    let mut map = std::collections::HashMap::new();
    for a in accepted {
        for inp in &a.op.inputs {
            map.remove(&inp.prev_seal);
        }
        for o in &a.op.outputs {
            let resolved = o.seal.resolved(&a.l1_txid);
            map.insert(resolved, (o.amount, o.pubkey, a.contract_id));
        }
    }
    map.into_iter()
        .map(|(seal, (amount, pk, cid))| (seal, amount, pk, cid))
        .collect()
}
