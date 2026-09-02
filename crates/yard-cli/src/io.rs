//! Consignment load / save / backup / inspect.
//!
//! A `.yard` file is the history a receiver needs to spend a note. If they
//! lose it and have no backup, the note cannot be spent even if they still
//! hold the seal UTXO (that UTXO remains ordinary DOGE).

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use yard_core::{open_notes, validate_consignment, Consignment, GenesisMeta, OpType};

pub fn load_consignment(path: &Path) -> Result<Consignment> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Consignment::decode_any(&bytes).map_err(|e| anyhow::anyhow!(e))
}

pub fn write_consignment(path: &Path, c: &Consignment) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, c.encode_binary()?).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

pub fn persist(path: &Path, c: &Consignment, backup_dir: &Path, no_backup: bool) -> Result<()> {
    write_consignment(path, c)?;
    eprintln!("consignment: {}", path.display());
    if no_backup {
        eprintln!("backup skipped (--no-backup). Losing this file loses the note.");
        return Ok(());
    }
    match backup_consignment(c, backup_dir) {
        Ok(p) => {
            eprintln!("backup: {}", p.display());
            eprintln!("losing both copies loses the note, even if you still hold the seal UTXO.");
        }
        Err(e) => eprintln!("warning: backup to {} failed: {e:#}", backup_dir.display()),
    }
    Ok(())
}

pub fn backup_consignment(c: &Consignment, dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let label = consignment_label(c);
    let mut dest = dir.join(format!("{label}.yard"));
    if dest.exists() {
        for i in 2..1000 {
            dest = dir.join(format!("{label}-{i}.yard"));
            if !dest.exists() {
                break;
            }
        }
    }
    fs::write(&dest, c.encode_binary()?).with_context(|| format!("write {}", dest.display()))?;
    Ok(dest)
}

pub fn export_consignment(c: &Consignment, out: &Path, json: bool) -> Result<()> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let bytes = if json {
        c.encode_json()?
    } else {
        c.encode_binary()?
    };
    fs::write(out, bytes).with_context(|| format!("write {}", out.display()))?;
    Ok(())
}

pub fn consignment_label(c: &Consignment) -> String {
    match validate_consignment(c) {
        Ok(accepted) => {
            if let Some(g) = accepted.first() {
                let tick = GenesisMeta::from_bytes(&g.op.meta)
                    .map(|m| m.tick)
                    .unwrap_or_else(|_| "NOTE".into());
                let last = accepted
                    .last()
                    .map(|a| a.op.op_type)
                    .unwrap_or(OpType::Genesis);
                let tag = match last {
                    OpType::Genesis => "g",
                    OpType::Transfer => "t",
                    OpType::Burn => "b",
                    OpType::LaunchBuy => "lb",
                    OpType::LaunchSell => "ls",
                };
                return format!("{}-{tag}", g.contract_id.display_with_tick(&tick));
            }
        }
        Err(_) => {}
    }
    "yard-unknown".into()
}

/// Always print `TICK-a1b2c3d4`, never the ticker alone.
pub fn print_show(c: &Consignment) -> Result<()> {
    let accepted = validate_consignment(c).map_err(|e| anyhow::anyhow!(e))?;
    let g = accepted
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty consignment"))?;
    let meta = GenesisMeta::from_bytes(&g.op.meta).ok();
    let tick = meta.as_ref().map(|m| m.tick.as_str()).unwrap_or("?");
    let label = g.contract_id.display_with_tick(tick);
    println!("contract: {label}");
    println!("contract_id: {}", g.contract_id);
    println!("tick: {tick} (not unique; wallets must show the contract line above)");
    if let Some(m) = &meta {
        println!("name: {}", m.name);
        println!("decimals: {} (display only)", m.dec);
        println!("max: {}", m.max);
        if let Some(l) = &m.launch {
            println!("launch.curve: {}", l.curve);
            println!("launch.treasury_pkh: {}", l.tr);
            if let Some(b) = &l.base {
                println!("launch.base_koinu: {b}");
            }
            if let Some(s) = &l.slope {
                println!("launch.slope: {s}");
            }
            if let Some(x) = &l.x {
                println!("launch.cpmm_x: {x}");
            }
        }
    }
    println!("ops: {}", accepted.len());
    let notes = open_notes(&accepted);
    if notes.is_empty() {
        println!("notes: none (fully burned or returned)");
    }
    for (seal, amt, pk, cid) in &notes {
        println!(
            "note {} {} amount {} pubkey {}",
            cid.display_with_tick(tick),
            seal,
            amt,
            hex::encode(pk)
        );
    }
    println!("backup this .yard file. Losing it loses the note.");
    Ok(())
}

pub fn contract_label_of(c: &Consignment) -> Result<String> {
    let accepted = validate_consignment(c).map_err(|e| anyhow::anyhow!(e))?;
    let g = accepted
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty consignment"))?;
    let tick = GenesisMeta::from_bytes(&g.op.meta)
        .map(|m| m.tick)
        .unwrap_or_else(|_| "?".into());
    Ok(g.contract_id.display_with_tick(&tick))
}

#[cfg(test)]
mod tests {
    use super::*;
    use yard_core::{
        compressed_pubkey, opreturn_script, p2pkh_script, test_secret, Amount, Commitment,
        ContractId, GenesisMeta, OpOutput, OpType, Operation, Outpoint, Transaction, TxIn, TxOut,
        SOFT_DUST_KOINU,
    };

    #[test]
    fn t_label_uses_tick_and_id() {
        let pk = compressed_pubkey(&test_secret());
        let mut op = Operation {
            op_version: 1,
            contract_id: ContractId::zeros(),
            op_type: OpType::Genesis,
            inputs: vec![],
            outputs: vec![OpOutput {
                seal: Outpoint::this_tx(1),
                amount: Amount(1),
                pubkey: pk,
            }],
            meta: GenesisMeta::new_ft("TEST", "Test Note", 8, 1, 0)
                .unwrap()
                .to_bytes()
                .unwrap(),
            sigs: vec![[0u8; 64]],
        };
        op.sign(0, &test_secret()).unwrap();
        let cm = Commitment::single(&op).unwrap();
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: Outpoint {
                    txid: [0x22; 32],
                    vout: 0,
                },
                script_sig: vec![0x00],
                sequence: 0xffffffff,
            }],
            vout: vec![
                TxOut {
                    value: 0,
                    script_pubkey: opreturn_script(&cm.encode()).unwrap(),
                },
                TxOut {
                    value: SOFT_DUST_KOINU,
                    script_pubkey: p2pkh_script(&[0x11; 20]),
                },
            ],
            lock_time: 0,
        };
        let c = Consignment::new(vec![op.clone()], vec![tx]);
        let label = consignment_label(&c);
        let cid = op.genesis_contract_id().unwrap();
        assert!(label.starts_with(&cid.display_with_tick("TEST")));
        assert!(!label.eq_ignore_ascii_case("TEST"));
        assert!(label.contains("-g"));
    }
}
