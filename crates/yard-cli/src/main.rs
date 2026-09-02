//! YARD CLI — issue, transfer, and verify notes on unmodified Dogecoin.
//!
//! Backup any `.yard` consignment you receive. If you lose it and have no
//! backup, you cannot spend the note even if you still hold the seal UTXO
//! (that UTXO remains ordinary DOGE).

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use secp256k1::{rand, SecretKey};
use std::fs;
use std::path::PathBuf;
use yard_core::{
    open_notes, validate_consignment, validate_ticker, Amount, Commitment, Consignment, ContractId,
    GenesisMeta, OpInput, OpOutput, OpType, Operation, Outpoint, SOFT_DUST_KOINU,
};
use yard_doge::{
    build_yard_tx, decode_address, decode_wif, encode_wif, hash160, p2pkh_address,
    parse_doge_to_koinu, Network, RpcClient, SealOutput, Spendable,
};
use yard_index::Index;

#[derive(Parser)]
#[command(
    name = "yard",
    version,
    about = "Client-side validated notes on unmodified Dogecoin.",
    long_about = "YARD is optional software. If you delete it, your DOGE is still DOGE.\n\n\
Backup `.yard` consignment files. Losing one means the note cannot be spent, even if you still hold the seal UTXO.\n\n\
This is not legal advice. Notes can go to zero. Tickers are not unique — wallets must show ContractId."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a Dogecoin P2PKH key. Prints address, pubkey, WIF. Warns loudly.
    NewKey {
        #[arg(long, default_value = "regtest")]
        network: String,
    },
    /// Issue a fixed-supply note (all units assigned at genesis).
    Genesis {
        #[arg(long, default_value = "regtest")]
        network: String,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        wif: String,
        #[arg(long)]
        tick: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = 8)]
        dec: u32,
        #[arg(long)]
        max: String,
        #[arg(long, default_value = "0.05")]
        seal_doge: String,
        #[arg(long, default_value = "testdata/last_genesis.yard")]
        out: PathBuf,
    },
    /// Transfer units from a consignment to a recipient pubkey/address.
    Transfer {
        #[arg(long)]
        consignment: PathBuf,
        /// Recipient Dogecoin address or compressed pubkey hex.
        #[arg(long)]
        to: String,
        /// Compressed secp256k1 pubkey hex (required if --to is an address).
        #[arg(long)]
        pubkey: Option<String>,
        #[arg(long)]
        amount: String,
        #[arg(long)]
        wif: String,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long, default_value = "regtest")]
        network: String,
        #[arg(long, default_value = "testdata/last_transfer.yard")]
        out: PathBuf,
        #[arg(long, default_value = "0.05")]
        seal_doge: String,
    },
    /// Fully validate a consignment against your own node. Exit 0 / 1.
    Verify {
        #[arg(long)]
        consignment: PathBuf,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long, default_value = "regtest")]
        network: String,
        /// G6. Default 6. Never 0 when note value exceeds dust.
        #[arg(long, default_value_t = 6)]
        confirmations: u64,
    },
    /// Print YARD commitments found on chain (indexer is a convenience).
    Scan {
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long, default_value = "regtest")]
        network: String,
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value = ":memory:")]
        db: String,
    },
}

fn parse_network(s: &str) -> Result<Network> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::NewKey { network } => cmd_new_key(parse_network(&network)?),
        Cmd::Genesis {
            network,
            rpc,
            wif,
            tick,
            name,
            dec,
            max,
            seal_doge,
            out,
        } => cmd_genesis(
            parse_network(&network)?,
            rpc.as_deref(),
            &wif,
            &tick,
            &name,
            dec,
            &max,
            &seal_doge,
            &out,
        ),
        Cmd::Transfer {
            consignment,
            to,
            pubkey,
            amount,
            wif,
            rpc,
            network,
            out,
            seal_doge,
        } => cmd_transfer(
            parse_network(&network)?,
            rpc.as_deref(),
            &consignment,
            &to,
            pubkey.as_deref(),
            &amount,
            &wif,
            &out,
            &seal_doge,
        ),
        Cmd::Verify {
            consignment,
            rpc,
            network,
            confirmations,
        } => cmd_verify(
            parse_network(&network)?,
            rpc.as_deref(),
            &consignment,
            confirmations,
        ),
        Cmd::Scan {
            rpc,
            network,
            from,
            db,
        } => cmd_scan(parse_network(&network)?, rpc.as_deref(), from, &db),
    }
}

fn cmd_new_key(network: Network) -> Result<()> {
    eprintln!("WARNING: this WIF can spend real DOGE. Anyone who sees it can take funds.");
    eprintln!("WARNING: backup `.yard` consignments. Losing the file loses the note.");
    eprintln!("This key is intended for regtest/dev unless you know otherwise.");
    let mut rng = rand::thread_rng();
    let sk = SecretKey::new(&mut rng);
    let pk = yard_core::compressed_pubkey(&sk);
    let addr = p2pkh_address(network, &pk);
    let wif = encode_wif(network, &sk, true);
    println!("network: {:?}", network);
    println!("address: {addr}");
    println!("pubkey: {}", hex::encode(pk));
    println!("wif: {wif}");
    Ok(())
}

fn cmd_genesis(
    network: Network,
    rpc_url: Option<&str>,
    wif: &str,
    tick: &str,
    name: &str,
    dec: u32,
    max: &str,
    seal_doge: &str,
    out: &PathBuf,
) -> Result<()> {
    validate_ticker(tick).map_err(|e| anyhow::anyhow!(e))?;
    let max_n: u128 = max.parse().context("max must be a u128 decimal string")?;
    let seal_val = parse_doge_to_koinu(seal_doge)?;
    if seal_val < SOFT_DUST_KOINU {
        bail!("--seal-doge must be >= 0.01 (soft dust)");
    }
    let (_net, sk, _) = decode_wif(wif)?;
    let pk = yard_core::compressed_pubkey(&sk);
    let addr = p2pkh_address(network, &pk);
    let rpc = RpcClient::for_network(network, rpc_url)?;

    let utxos = rpc.listunspent(1, &[addr.clone()])?;
    if utxos.is_empty() {
        bail!("no confirmed UTXOs for {addr}. Mine to this address on regtest.");
    }
    let mut op = Operation {
        op_version: 1,
        contract_id: ContractId::zeros(),
        op_type: OpType::Genesis,
        inputs: vec![],
        outputs: vec![OpOutput {
            seal: Outpoint::this_tx(1),
            amount: Amount(max_n),
            pubkey: pk,
        }],
        meta: GenesisMeta::new_ft(tick, name, dec, max_n, 0)?.to_bytes()?,
        sigs: vec![[0u8; 64]],
    };
    op.sign(0, &sk)?;
    let cm = Commitment::single(&op)?;
    let spends = select_inputs(&utxos, &sk, seal_val)?;
    let change_pkh = Some(hash160(&pk));
    let tx = build_yard_tx(
        &spends,
        &[SealOutput {
            value: seal_val,
            pubkey: pk,
        }],
        change_pkh,
        &cm,
    )?;
    let hex = hex::encode(tx.encode());
    let txid = rpc.sendrawtransaction(&hex)?;
    let cid = op.genesis_contract_id()?;
    let cons = Consignment::new(vec![op], vec![tx]);
    write_consignment(out, &cons)?;
    println!("broadcast: {txid}");
    println!("contract: {}", cid.display_with_tick(tick));
    println!("contract_id: {cid}");
    println!("consignment: {}", out.display());
    println!("backup this .yard file. Losing it loses the note.");
    Ok(())
}

fn cmd_transfer(
    network: Network,
    rpc_url: Option<&str>,
    consignment: &PathBuf,
    to: &str,
    pubkey_arg: Option<&str>,
    amount: &str,
    wif: &str,
    out: &PathBuf,
    seal_doge: &str,
) -> Result<()> {
    let amount: u128 = amount.parse().context("amount must be a u128")?;
    let seal_val = parse_doge_to_koinu(seal_doge)?;
    if seal_val < SOFT_DUST_KOINU {
        bail!("--seal-doge must be >= 0.01");
    }
    let dest_pk = parse_dest_pubkey(network, to, pubkey_arg)?;
    let (_net, sk, _) = decode_wif(wif)?;
    let our_pk = yard_core::compressed_pubkey(&sk);
    let our_addr = p2pkh_address(network, &our_pk);
    let rpc = RpcClient::for_network(network, rpc_url)?;

    let cons = load_consignment(consignment)?;
    let accepted = validate_consignment(&cons)?;
    let notes = open_notes(&accepted);
    let note = notes
        .iter()
        .find(|(_, _, pk, _)| *pk == our_pk)
        .with_context(|| "no open note in this consignment for this WIF")?;
    let (seal, note_amt, _pk, cid) = note.clone();
    if amount > note_amt.0 {
        bail!("amount {amount} exceeds note {}", note_amt.0);
    }

    let mut outputs = vec![OpOutput {
        seal: Outpoint::this_tx(1),
        amount: Amount(amount),
        pubkey: dest_pk,
    }];
    let mut seals = vec![SealOutput {
        value: seal_val,
        pubkey: dest_pk,
    }];
    if amount < note_amt.0 {
        outputs.push(OpOutput {
            seal: Outpoint::this_tx(2),
            amount: Amount(note_amt.0 - amount),
            pubkey: our_pk,
        });
        seals.push(SealOutput {
            value: seal_val,
            pubkey: our_pk,
        });
    }

    let prev_op = accepted
        .iter()
        .rev()
        .find(|a| {
            a.op.outputs
                .iter()
                .any(|o| o.seal.resolved(&a.l1_txid) == seal)
        })
        .context("no accepted op created this seal")?;
    let mut xfer = Operation {
        op_version: 1,
        contract_id: cid,
        op_type: OpType::Transfer,
        inputs: vec![OpInput {
            prev_op_hash: prev_op.op.op_hash()?,
            prev_seal: seal,
            amount: note_amt,
        }],
        outputs,
        meta: vec![],
        sigs: vec![[0u8; 64]],
    };
    xfer.sign(0, &sk)?;
    let cm = Commitment::single(&xfer)?;

    let mut spends = vec![seal_spend(&rpc, &seal, &sk)?];
    let extra = rpc.listunspent(1, &[our_addr])?;
    let need: u64 = seals.iter().map(|s| s.value).sum::<u64>() + 2_000_000;
    let have: u64 = spends.iter().map(|s| s.value).sum();
    if have < need {
        for u in extra {
            if u.prevout == seal {
                continue;
            }
            let script = if u.script_hex.is_empty() {
                yard_core::p2pkh_script(&hash160(&our_pk))
            } else {
                hex::decode(&u.script_hex)
                    .unwrap_or_else(|_| yard_core::p2pkh_script(&hash160(&our_pk)))
            };
            spends.push(Spendable {
                prevout: u.prevout,
                value: u.amount_koinu,
                script_pubkey: script,
                secret: sk,
            });
            if spends.iter().map(|s| s.value).sum::<u64>() >= need {
                break;
            }
        }
    }
    let tx = build_yard_tx(&spends, &seals, Some(hash160(&our_pk)), &cm)?;
    let hex = hex::encode(tx.encode());
    let txid = rpc.sendrawtransaction(&hex)?;

    let mut ops = cons.ops.clone();
    ops.push(xfer);
    let mut txs = cons.txs.clone();
    txs.push(tx);
    let out_cons = Consignment::new(ops, txs);
    write_consignment(out, &out_cons)?;
    println!("broadcast: {txid}");
    println!("consignment: {}", out.display());
    println!("backup this .yard file. Losing it loses the note.");
    Ok(())
}

fn cmd_verify(
    network: Network,
    rpc_url: Option<&str>,
    path: &PathBuf,
    confirmations: u64,
) -> Result<()> {
    let cons = load_consignment(path)?;
    let accepted = validate_consignment(&cons)?;
    let genesis = accepted.first().context("no genesis")?;
    let meta = GenesisMeta::from_bytes(&genesis.op.meta).ok();
    let tick = meta.as_ref().map(|m| m.tick.as_str()).unwrap_or("?");

    let notes = open_notes(&accepted);
    let max_value = notes.iter().map(|n| n.1 .0).max().unwrap_or(0);
    if confirmations == 0 && max_value > 0 {
        bail!("G6: never N = 0 for value > dust");
    }

    let rpc = RpcClient::for_network(network, rpc_url)?;
    for a in &accepted {
        let rpc_txid = yard_core::rpc_hex(&a.l1_txid);
        match rpc.get_tx_confirmations(&rpc_txid)? {
            Some(c) if c >= confirmations => {}
            Some(c) => {
                bail!("G6: {rpc_txid} has {c} confirmations, need {confirmations}");
            }
            None => bail!("G6: {rpc_txid} is not in the node's best chain"),
        }
    }
    println!("ok");
    println!("contract: {}", genesis.contract_id.display_with_tick(tick));
    println!("ops: {}", accepted.len());
    for (seal, amt, pk, _) in notes {
        println!("note {} amount {} pubkey {}", seal, amt, hex::encode(pk));
    }
    Ok(())
}

fn cmd_scan(network: Network, rpc_url: Option<&str>, from: u64, db: &str) -> Result<()> {
    let rpc = RpcClient::for_network(network, rpc_url)?;
    let mut idx = Index::open(db)?;
    let found = idx.sync(&rpc, from)?;
    println!("scanned from {from}; found {} commitment(s)", found.len());
    for c in found {
        println!(
            "height={} txid={} root={}",
            c.height, c.txid_rpc, c.root_hex
        );
    }
    Ok(())
}

fn load_consignment(path: &PathBuf) -> Result<Consignment> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Consignment::decode_any(&bytes).map_err(|e| anyhow::anyhow!(e))
}

fn write_consignment(path: &PathBuf, c: &Consignment) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, c.encode_binary()?).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn parse_dest_pubkey(network: Network, to: &str, pubkey: Option<&str>) -> Result<[u8; 33]> {
    if let Some(p) = pubkey {
        let pk = hex_pk(p)?;
        if !to.chars().all(|c| c.is_ascii_hexdigit()) {
            let addr = p2pkh_address(network, &pk);
            if to != addr {
                bail!("--to {to} does not match --pubkey (expected {addr})");
            }
        }
        return Ok(pk);
    }
    if to.len() == 66 && to.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex_pk(to);
    }
    let _ = decode_address(to)?;
    bail!("--to is an address; pass --pubkey <compressed hex> (addresses are HASH160, not pubkeys)")
}

fn hex_pk(s: &str) -> Result<[u8; 33]> {
    let b = hex::decode(s.trim()).context("pubkey hex")?;
    if b.len() != 33 {
        bail!("compressed pubkey must be 33 bytes");
    }
    if b[0] != 0x02 && b[0] != 0x03 {
        bail!("pubkey is not compressed");
    }
    let mut a = [0u8; 33];
    a.copy_from_slice(&b);
    Ok(a)
}

fn select_inputs(
    utxos: &[yard_doge::Utxo],
    sk: &SecretKey,
    seal_val: u64,
) -> Result<Vec<Spendable>> {
    let pk = yard_core::compressed_pubkey(sk);
    let fallback = yard_core::p2pkh_script(&hash160(&pk));
    let mut sorted = utxos.to_vec();
    sorted.sort_by_key(|u| std::cmp::Reverse(u.amount_koinu));
    let need = seal_val.saturating_add(2_000_000);
    let mut out = Vec::new();
    let mut sum = 0u64;
    for u in sorted {
        let script = if u.script_hex.is_empty() {
            fallback.clone()
        } else {
            hex::decode(&u.script_hex).unwrap_or_else(|_| fallback.clone())
        };
        out.push(Spendable {
            prevout: u.prevout,
            value: u.amount_koinu,
            script_pubkey: script,
            secret: *sk,
        });
        sum += u.amount_koinu;
        if sum >= need {
            return Ok(out);
        }
    }
    bail!("insufficient confirmed UTXOs (need about {} koinu)", need)
}

fn seal_spend(rpc: &RpcClient, seal: &Outpoint, sk: &SecretKey) -> Result<Spendable> {
    let rpc_txid = yard_core::rpc_hex(&seal.txid);
    let tx = rpc.fetch_tx(&rpc_txid)?;
    let out = tx
        .output(seal.vout)
        .with_context(|| format!("seal {seal} missing on L1"))?;
    Ok(Spendable {
        prevout: *seal,
        value: out.value,
        script_pubkey: out.script_pubkey.clone(),
        secret: *sk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spawns nothing. Documents the regtest path. Ignored unless a node is up
    /// and YARD_REGTEST=1.
    ///
    ///     dogecoind -regtest -server -txindex -rpcuser=yard -rpcpassword=yard -rpcport=18332
    ///     dogecoin-cli -regtest -rpcuser=yard -rpcpassword=yard generatetoaddress 110 D...
    ///     yard genesis --network regtest --rpc http://yard:yard@127.0.0.1:18332 --wif ... --tick TEST --name Test --dec 8 --max 21000000000000000 --seal-doge 0.05
    ///     yard transfer --consignment testdata/last_genesis.yard --to <pubkey> --amount 1000 --wif ... --rpc http://yard:yard@127.0.0.1:18332
    ///     yard verify --consignment testdata/last_transfer.yard --rpc http://yard:yard@127.0.0.1:18332
    #[test]
    #[ignore]
    fn testdoge_regtest_genesis_and_transfer() {
        if std::env::var("YARD_REGTEST").ok().as_deref() != Some("1") {
            eprintln!("set YARD_REGTEST=1 and run a dogecoind -regtest node");
            return;
        }
        let rpc = RpcClient::from_url("http://yard:yard@127.0.0.1:18332").expect("rpc url");
        let _ = rpc.getblockcount().expect("dogecoind not reachable");
    }
}
