use crate::consignment::Consignment;
use crate::l1::{is_p2pkh, Transaction};
use crate::launch::LaunchSpec;
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
    let info = launch_info(prev);
    // T8
    if !op.op_type.allowed_for(info.enabled) {
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
        OpType::Transfer | OpType::Burn => validate_spend(op, prev, l1_tx, &l1_txid, info.pool_pk)?,
        OpType::LaunchBuy => {
            validate_spend(op, prev, l1_tx, &l1_txid, info.pool_pk)?;
            validate_launch_buy(op, prev, l1_tx, &info)?;
        }
        OpType::LaunchSell => {
            validate_spend(op, prev, l1_tx, &l1_txid, info.pool_pk)?;
            validate_launch_sell(op, prev, l1_tx, &info)?;
        }
    }
    Ok(())
}

struct LaunchInfo {
    enabled: bool,
    spec: Option<LaunchSpec>,
    pool_pk: Option<[u8; 33]>,
    pool0: Amount,
}

fn launch_info(prev: &[AcceptedOp]) -> LaunchInfo {
    let none = LaunchInfo {
        enabled: false,
        spec: None,
        pool_pk: None,
        pool0: Amount::ZERO,
    };
    let Some(g) = prev.first() else {
        return none;
    };
    if g.op.op_type != OpType::Genesis {
        return none;
    }
    let Ok(meta) = GenesisMeta::from_bytes(&g.op.meta) else {
        return none;
    };
    match meta.launch {
        Some(spec) => LaunchInfo {
            enabled: true,
            spec: Some(spec),
            pool_pk: g.op.outputs.first().map(|o| o.pubkey),
            pool0: g
                .op
                .outputs
                .first()
                .map(|o| o.amount)
                .unwrap_or(Amount::ZERO),
        },
        None => none,
    }
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

/// T1–T8 for transfer, burn, and launch spends.
fn validate_spend(
    op: &Operation,
    prev: &[AcceptedOp],
    l1_tx: &Transaction,
    l1_txid: &[u8; 32],
    pool_pk: Option<[u8; 33]>,
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
        OpType::Transfer | OpType::LaunchBuy | OpType::LaunchSell => {
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
        // Pool inventory of a launch contract is not a transferable note.
        if let Some(pk) = pool_pk {
            if assigned == pk && !matches!(op.op_type, OpType::LaunchBuy | OpType::LaunchSell) {
                return Err(Error::T8);
            }
        }
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

/// L3–L6: spend the pool, split purchased units to one buyer, pay the curve
/// in L1 DOGE to the treasury (excluding seal outputs).
fn validate_launch_buy(
    op: &Operation,
    prev: &[AcceptedOp],
    l1_tx: &Transaction,
    info: &LaunchInfo,
) -> Result<(), Error> {
    let spec = info.spec.as_ref().ok_or(Error::T8)?;
    let pool_pk = info.pool_pk.ok_or(Error::T8)?;
    if op.inputs.len() != 1 {
        return Err(Error::Decode(
            "launch_buy must spend exactly the pool seal".into(),
        ));
    }
    let (prev_op, prev_txid) = find_prev(prev, &op.inputs[0].prev_op_hash)?;
    let assigned = find_assigned(
        prev_op,
        prev_txid,
        &op.inputs[0].prev_seal,
        op.inputs[0].amount,
    )?;
    if assigned != pool_pk {
        return Err(Error::Decode("launch_buy must spend the pool seal".into()));
    }
    let pool_in = op.inputs[0].amount;
    let pool_out = op
        .outputs
        .iter()
        .filter(|o| o.pubkey == pool_pk)
        .try_fold(Amount::ZERO, |a, o| a.checked_add(o.amount))
        .ok_or_else(|| Error::Decode("pool remainder overflow".into()))?;
    if op.outputs.iter().filter(|o| o.pubkey == pool_pk).count() > 1 {
        return Err(Error::Decode("launch_buy has multiple pool outputs".into()));
    }
    let bought = pool_in
        .checked_sub(pool_out)
        .ok_or_else(|| Error::Decode("pool remainder exceeds pool input".into()))?;
    if bought.0 == 0 {
        return Err(Error::Decode("launch_buy amount is 0".into()));
    }
    let buyers: Vec<_> = op.outputs.iter().filter(|o| o.pubkey != pool_pk).collect();
    if buyers.len() != 1 || buyers[0].amount != bought {
        return Err(Error::Decode(
            "launch_buy must assign purchased units to exactly one buyer output".into(),
        ));
    }
    let cost = spec.buy_cost(info.pool0.0, pool_in.0, bought.0)?;
    let treasury = spec.treasury_pkh()?;
    let paid = non_seal_paid_to(l1_tx, &treasury, op);
    if (paid as u128) < cost {
        return Err(Error::LaunchPay);
    }
    Ok(())
}

/// L7–L8: spend pool + seller note, return units to the pool, pay the refund
/// in L1 DOGE to the seller (excluding seal outputs). Anyone may fund it.
fn validate_launch_sell(
    op: &Operation,
    prev: &[AcceptedOp],
    l1_tx: &Transaction,
    info: &LaunchInfo,
) -> Result<(), Error> {
    let spec = info.spec.as_ref().ok_or(Error::T8)?;
    let pool_pk = info.pool_pk.ok_or(Error::T8)?;
    if op.inputs.len() != 2 {
        return Err(Error::Decode(
            "launch_sell must spend the pool seal and one seller note".into(),
        ));
    }
    let mut pool_in: Option<Amount> = None;
    let mut seller_pk: Option<[u8; 33]> = None;
    let mut seller_in = Amount::ZERO;
    for inp in &op.inputs {
        let (prev_op, prev_txid) = find_prev(prev, &inp.prev_op_hash)?;
        let assigned = find_assigned(prev_op, prev_txid, &inp.prev_seal, inp.amount)?;
        if assigned == pool_pk {
            if pool_in.is_some() {
                return Err(Error::Decode("launch_sell spends pool twice".into()));
            }
            pool_in = Some(inp.amount);
        } else {
            if seller_pk.is_some() {
                return Err(Error::Decode(
                    "launch_sell must have exactly one seller input".into(),
                ));
            }
            seller_pk = Some(assigned);
            seller_in = inp.amount;
        }
    }
    let pool_in = pool_in.ok_or_else(|| Error::Decode("launch_sell missing pool input".into()))?;
    let seller_pk =
        seller_pk.ok_or_else(|| Error::Decode("launch_sell missing seller input".into()))?;

    let pool_out = op
        .outputs
        .iter()
        .filter(|o| o.pubkey == pool_pk)
        .try_fold(Amount::ZERO, |a, o| a.checked_add(o.amount))
        .ok_or_else(|| Error::Decode("pool output overflow".into()))?;
    if op.outputs.iter().filter(|o| o.pubkey == pool_pk).count() != 1 {
        return Err(Error::Decode(
            "launch_sell must have exactly one pool output".into(),
        ));
    }
    let returned = pool_out
        .checked_sub(pool_in)
        .ok_or_else(|| Error::Decode("launch_sell did not return units to the pool".into()))?;
    if returned.0 == 0 {
        return Err(Error::Decode("launch_sell amount is 0".into()));
    }
    let seller_out = op
        .outputs
        .iter()
        .filter(|o| o.pubkey == seller_pk)
        .try_fold(Amount::ZERO, |a, o| a.checked_add(o.amount))
        .ok_or_else(|| Error::Decode("seller remainder overflow".into()))?;
    if seller_out
        .checked_add(returned)
        .ok_or_else(|| Error::Decode("seller remainder overflow".into()))?
        != seller_in
    {
        return Err(Error::Decode(
            "launch_sell seller in != remainder + returned".into(),
        ));
    }
    let refund = spec.sell_refund(info.pool0.0, pool_in.0, returned.0)?;
    if refund == 0 {
        return Err(Error::LaunchPay);
    }
    let seller_pkh = crate::hash160(&seller_pk);
    let paid = non_seal_paid_to(l1_tx, &seller_pkh, op);
    if (paid as u128) < refund {
        return Err(Error::LaunchPay);
    }
    Ok(())
}

fn non_seal_paid_to(l1_tx: &Transaction, pkh: &[u8; 20], op: &Operation) -> u64 {
    let seal_vouts: HashSet<u32> = op.outputs.iter().map(|o| o.seal.vout).collect();
    let mut sum = 0u64;
    for (i, o) in l1_tx.vout.iter().enumerate() {
        if seal_vouts.contains(&(i as u32)) {
            continue;
        }
        if let Some(h) = is_p2pkh(&o.script_pubkey) {
            if h == *pkh {
                sum = sum.saturating_add(o.value);
            }
        }
    }
    sum
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
