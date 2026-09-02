//! YARD CLI — issue, transfer, burn, launch, and verify notes on unmodified Dogecoin.
//!
//! Backup any `.yard` consignment you receive. If you lose it and have no
//! backup, you cannot spend the note even if you still hold the seal UTXO
//! (that UTXO remains ordinary DOGE). Tickers are not unique: wallets must
//! show `TICK-a1b2c3d4`.

mod io;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use secp256k1::{rand, SecretKey};
use std::path::PathBuf;
use yard_core::{
    open_notes, validate_consignment, validate_ticker, Amount, Commitment, Consignment, ContractId,
    GenesisMeta, LaunchSpec, OpInput, OpOutput, OpType, Operation, Outpoint, SOFT_DUST_KOINU,
};
use yard_doge::{
    build_yard_tx, build_yard_tx_with_pays, decode_address, decode_wif, encode_wif, hash160,
    koinu_to_doge_string, p2pkh_address, p2pkh_address_from_pkh, parse_doge_to_koinu,
    pkh_from_p2pkh_address, Network, PayOutput, RpcClient, SealOutput, Spendable,
};
use yard_index::Index;

use crate::io::{
    backup_consignment, contract_label_of, export_consignment, load_consignment, persist,
    print_show,
};

#[derive(Parser)]
#[command(
    name = "yard",
    version,
    about = "Client-side validated notes on unmodified Dogecoin.",
    long_about = "YARD is optional software. If you delete it, your DOGE is still DOGE.\n\n\
Backup `.yard` consignment files. Losing one means the note cannot be spent, even if you still hold the seal UTXO.\n\n\
Tickers are not unique — wallets must show ContractId as TICK-a1b2c3d4.\n\n\
This is not legal advice. Notes can go to zero."
)]
struct Cli {
    /// Second copy of every written .yard file. Losing both copies loses the note.
    #[arg(long, global = true, default_value = ".yard")]
    backup_dir: PathBuf,
    /// Do not write a backup copy.
    #[arg(long, global = true)]
    no_backup: bool,
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
        /// Phase 1: `lin` or `cpmm`. Genesis output[0] becomes the pool.
        #[arg(long)]
        curve: Option<String>,
        /// Treasury P2PKH address that receives L1 DOGE from buys.
        #[arg(long)]
        treasury: Option<String>,
        /// Linear: koinu per unit at sold=0.
        #[arg(long)]
        base: Option<String>,
        /// Linear: extra koinu per unit per unit already sold (default 0).
        #[arg(long)]
        slope: Option<String>,
        /// CPMM: initial virtual DOGE reserve in koinu.
        #[arg(long)]
        cpmm_x: Option<String>,
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
    /// Burn units. Remainder stays on a change note to the same key.
    Burn {
        #[arg(long)]
        consignment: PathBuf,
        #[arg(long)]
        amount: String,
        #[arg(long)]
        wif: String,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long, default_value = "regtest")]
        network: String,
        #[arg(long, default_value = "testdata/last_burn.yard")]
        out: PathBuf,
        #[arg(long, default_value = "0.05")]
        seal_doge: String,
    },
    /// Inspect a consignment. Always prints TICK-a1b2c3d4, never ticker alone.
    Show {
        #[arg(long)]
        consignment: PathBuf,
    },
    /// Copy a consignment (binary default, or JSON).
    Export {
        #[arg(long)]
        consignment: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Write a second copy into --backup-dir (default .yard).
    Backup {
        #[arg(long)]
        consignment: PathBuf,
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
    /// Buy from a launch pool. Pays L1 DOGE to the genesis treasury.
    LaunchBuy {
        #[arg(long)]
        consignment: PathBuf,
        /// Buyer compressed pubkey hex (or address + --pubkey).
        #[arg(long)]
        to: String,
        #[arg(long)]
        pubkey: Option<String>,
        #[arg(long)]
        amount: String,
        /// Funder WIF (pays treasury + fees + new seals). Defaults to also being the pool.
        #[arg(long)]
        wif: String,
        /// Pool inventory WIF if different from --wif.
        #[arg(long)]
        pool_wif: Option<String>,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long, default_value = "regtest")]
        network: String,
        #[arg(long, default_value = "testdata/last_launch_buy.yard")]
        out: PathBuf,
        #[arg(long, default_value = "0.05")]
        seal_doge: String,
    },
    /// Sell units back into the pool. Refund is L1 DOGE to the seller.
    LaunchSell {
        #[arg(long)]
        consignment: PathBuf,
        #[arg(long)]
        amount: String,
        /// Seller WIF.
        #[arg(long)]
        wif: String,
        /// Pool inventory WIF.
        #[arg(long)]
        pool_wif: String,
        /// Optional funder of the refund (defaults to --wif).
        #[arg(long)]
        pay_wif: Option<String>,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long, default_value = "regtest")]
        network: String,
        #[arg(long, default_value = "testdata/last_launch_sell.yard")]
        out: PathBuf,
        #[arg(long, default_value = "0.05")]
        seal_doge: String,
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
    let persist_dir = cli.backup_dir.clone();
    let no_backup = cli.no_backup;
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
            curve,
            treasury,
            base,
            slope,
            cpmm_x,
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
            curve.as_deref(),
            treasury.as_deref(),
            base.as_deref(),
            slope.as_deref(),
            cpmm_x.as_deref(),
            &persist_dir,
            no_backup,
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
            &persist_dir,
            no_backup,
        ),
        Cmd::Burn {
            consignment,
            amount,
            wif,
            rpc,
            network,
            out,
            seal_doge,
        } => cmd_burn(
            parse_network(&network)?,
            rpc.as_deref(),
            &consignment,
            &amount,
            &wif,
            &out,
            &seal_doge,
            &persist_dir,
            no_backup,
        ),
        Cmd::Show { consignment } => {
            let c = load_consignment(&consignment)?;
            print_show(&c)
        }
        Cmd::Export {
            consignment,
            out,
            json,
        } => {
            let c = load_consignment(&consignment)?;
            export_consignment(&c, &out, json)?;
            println!("wrote {}", out.display());
            Ok(())
        }
        Cmd::Backup { consignment } => {
            let c = load_consignment(&consignment)?;
            let p = backup_consignment(&c, &persist_dir)?;
            println!("backup: {}", p.display());
            Ok(())
        }
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
        Cmd::LaunchBuy {
            consignment,
            to,
            pubkey,
            amount,
            wif,
            pool_wif,
            rpc,
            network,
            out,
            seal_doge,
        } => cmd_launch_buy(
            parse_network(&network)?,
            rpc.as_deref(),
            &consignment,
            &to,
            pubkey.as_deref(),
            &amount,
            &wif,
            pool_wif.as_deref(),
            &out,
            &seal_doge,
            &persist_dir,
            no_backup,
        ),
        Cmd::LaunchSell {
            consignment,
            amount,
            wif,
            pool_wif,
            pay_wif,
            rpc,
            network,
            out,
            seal_doge,
        } => cmd_launch_sell(
            parse_network(&network)?,
            rpc.as_deref(),
            &consignment,
            &amount,
            &wif,
            &pool_wif,
            pay_wif.as_deref(),
            &out,
            &seal_doge,
            &persist_dir,
            no_backup,
        ),
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
    curve: Option<&str>,
    treasury: Option<&str>,
    base: Option<&str>,
    slope: Option<&str>,
    cpmm_x: Option<&str>,
    backup_dir: &PathBuf,
    no_backup: bool,
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

    let mut meta = GenesisMeta::new_ft(tick, name, dec, max_n, 0)?;
    if let Some(curve) = curve {
        let addr = treasury.context("--treasury is required with --curve")?;
        let pkh = pkh_from_p2pkh_address(addr)?;
        meta.launch = Some(match curve {
            "lin" => {
                let base: u128 = base
                    .context("--base is required for --curve lin")?
                    .parse()
                    .context("base")?;
                let slope: u128 = slope.unwrap_or("0").parse().context("slope")?;
                LaunchSpec::linear(&pkh, base, slope).map_err(|e| anyhow::anyhow!(e))?
            }
            "cpmm" => {
                let x: u128 = cpmm_x
                    .context("--cpmm-x is required for --curve cpmm")?
                    .parse()
                    .context("cpmm-x")?;
                LaunchSpec::cpmm(&pkh, x).map_err(|e| anyhow::anyhow!(e))?
            }
            other => bail!("--curve must be lin or cpmm, got {other}"),
        });
        meta.validate().map_err(|e| anyhow::anyhow!(e))?;
    }

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
        meta: meta.to_bytes().map_err(|e| anyhow::anyhow!(e))?,
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
    persist(out, &cons, backup_dir, no_backup)?;
    println!("broadcast: {txid}");
    println!("contract: {}", cid.display_with_tick(tick));
    println!("contract_id: {cid}");
    if meta.launch.is_some() {
        println!("launch: pool is genesis output 0 (this key). Buys pay L1 DOGE to --treasury.");
    }
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
    backup_dir: &PathBuf,
    no_backup: bool,
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
    add_funding(&mut spends, &extra, &sk, need, &[seal])?;
    let tx = build_yard_tx(&spends, &seals, Some(hash160(&our_pk)), &cm)?;
    let hex = hex::encode(tx.encode());
    let txid = rpc.sendrawtransaction(&hex)?;

    let mut ops = cons.ops.clone();
    ops.push(xfer);
    let mut txs = cons.txs.clone();
    txs.push(tx);
    let out_cons = Consignment::new(ops, txs);
    persist(out, &out_cons, backup_dir, no_backup)?;
    println!("broadcast: {txid}");
    println!("contract: {}", contract_label_of(&out_cons)?);
    Ok(())
}

fn cmd_burn(
    network: Network,
    rpc_url: Option<&str>,
    consignment: &PathBuf,
    amount: &str,
    wif: &str,
    out: &PathBuf,
    seal_doge: &str,
    backup_dir: &PathBuf,
    no_backup: bool,
) -> Result<()> {
    let amount: u128 = amount.parse().context("amount must be a u128")?;
    if amount == 0 {
        bail!("burn amount must be > 0");
    }
    let seal_val = parse_doge_to_koinu(seal_doge)?;
    if seal_val < SOFT_DUST_KOINU {
        bail!("--seal-doge must be >= 0.01");
    }
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

    let mut outputs = Vec::new();
    let mut seals = Vec::new();
    if amount < note_amt.0 {
        outputs.push(OpOutput {
            seal: Outpoint::this_tx(1),
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
    let mut burn = Operation {
        op_version: 1,
        contract_id: cid,
        op_type: OpType::Burn,
        inputs: vec![OpInput {
            prev_op_hash: prev_op.op.op_hash()?,
            prev_seal: seal,
            amount: note_amt,
        }],
        outputs,
        meta: vec![],
        sigs: vec![[0u8; 64]],
    };
    burn.sign(0, &sk)?;
    let cm = Commitment::single(&burn)?;

    let mut spends = vec![seal_spend(&rpc, &seal, &sk)?];
    let extra = rpc.listunspent(1, &[our_addr])?;
    let need: u64 = seals.iter().map(|s| s.value).sum::<u64>() + 2_000_000;
    add_funding(&mut spends, &extra, &sk, need, &[seal])?;
    let tx = build_yard_tx_with_pays(&spends, &seals, &[], Some(hash160(&our_pk)), &cm)?;
    let hex = hex::encode(tx.encode());
    let txid = rpc.sendrawtransaction(&hex)?;

    let mut ops = cons.ops.clone();
    ops.push(burn);
    let mut txs = cons.txs.clone();
    txs.push(tx);
    let out_cons = Consignment::new(ops, txs);
    persist(out, &out_cons, backup_dir, no_backup)?;
    println!("broadcast: {txid}");
    println!("contract: {}", contract_label_of(&out_cons)?);
    println!("burned: {amount}");
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
    for (seal, amt, pk, cid) in notes {
        println!(
            "note {} {} amount {} pubkey {}",
            cid.display_with_tick(tick),
            seal,
            amt,
            hex::encode(pk)
        );
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

fn cmd_launch_buy(
    network: Network,
    rpc_url: Option<&str>,
    consignment: &PathBuf,
    to: &str,
    pubkey_arg: Option<&str>,
    amount: &str,
    wif: &str,
    pool_wif: Option<&str>,
    out: &PathBuf,
    seal_doge: &str,
    backup_dir: &PathBuf,
    no_backup: bool,
) -> Result<()> {
    let amount: u128 = amount.parse().context("amount must be a u128")?;
    if amount == 0 {
        bail!("buy amount must be > 0");
    }
    let seal_val = parse_doge_to_koinu(seal_doge)?;
    if seal_val < SOFT_DUST_KOINU {
        bail!("--seal-doge must be >= 0.01");
    }
    let dest_pk = parse_dest_pubkey(network, to, pubkey_arg)?;
    let (_net, funder_sk, _) = decode_wif(wif)?;
    let pool_sk = match pool_wif {
        Some(w) => decode_wif(w)?.1,
        None => funder_sk,
    };
    let funder_pk = yard_core::compressed_pubkey(&funder_sk);
    let pool_pk = yard_core::compressed_pubkey(&pool_sk);
    let funder_addr = p2pkh_address(network, &funder_pk);
    let rpc = RpcClient::for_network(network, rpc_url)?;

    let cons = load_consignment(consignment)?;
    let accepted = validate_consignment(&cons)?;
    let genesis = accepted.first().context("no genesis")?;
    let meta = GenesisMeta::from_bytes(&genesis.op.meta)?;
    let spec = meta
        .launch
        .as_ref()
        .context("this contract has no launch spec")?;
    let genesis_pool_pk = genesis.op.outputs[0].pubkey;
    if genesis_pool_pk != pool_pk {
        bail!("--pool-wif / --wif does not match the launch pool pubkey");
    }
    let pool0 = genesis.op.outputs[0].amount;
    let notes = open_notes(&accepted);
    let pool = notes
        .iter()
        .find(|(_, _, pk, _)| *pk == pool_pk)
        .context("no open pool note in this consignment")?;
    let (pool_seal, pool_amt, _, cid) = pool.clone();
    if amount > pool_amt.0 {
        bail!("amount {amount} exceeds pool {}", pool_amt.0);
    }
    let remainder = pool_amt.0 - amount;
    let cost = spec.buy_cost(pool0.0, pool_amt.0, amount)?;
    let pay = relayable_pay(cost)?;
    let treasury = spec.treasury_pkh()?;

    let mut outputs = vec![OpOutput {
        seal: Outpoint::this_tx(1),
        amount: Amount(amount),
        pubkey: dest_pk,
    }];
    let mut seals = vec![SealOutput {
        value: seal_val,
        pubkey: dest_pk,
    }];
    if remainder > 0 {
        outputs.push(OpOutput {
            seal: Outpoint::this_tx(2),
            amount: Amount(remainder),
            pubkey: pool_pk,
        });
        seals.push(SealOutput {
            value: seal_val,
            pubkey: pool_pk,
        });
    }

    let prev_op = accepted
        .iter()
        .rev()
        .find(|a| {
            a.op.outputs
                .iter()
                .any(|o| o.seal.resolved(&a.l1_txid) == pool_seal)
        })
        .context("no accepted op created the pool seal")?;
    let mut buy = Operation {
        op_version: 1,
        contract_id: cid,
        op_type: OpType::LaunchBuy,
        inputs: vec![OpInput {
            prev_op_hash: prev_op.op.op_hash()?,
            prev_seal: pool_seal,
            amount: pool_amt,
        }],
        outputs,
        meta: vec![],
        sigs: vec![[0u8; 64]],
    };
    buy.sign(0, &pool_sk)?;
    let cm = Commitment::single(&buy)?;

    let mut spends = vec![seal_spend(&rpc, &pool_seal, &pool_sk)?];
    let extra = rpc.listunspent(1, &[funder_addr])?;
    let need: u64 = seals.iter().map(|s| s.value).sum::<u64>() + pay + 2_000_000;
    add_funding(&mut spends, &extra, &funder_sk, need, &[pool_seal])?;
    let pays = [PayOutput {
        value: pay,
        pkh: treasury,
    }];
    let tx = build_yard_tx_with_pays(&spends, &seals, &pays, Some(hash160(&funder_pk)), &cm)?;
    let hex = hex::encode(tx.encode());
    let txid = rpc.sendrawtransaction(&hex)?;

    let mut ops = cons.ops.clone();
    ops.push(buy);
    let mut txs = cons.txs.clone();
    txs.push(tx);
    let out_cons = Consignment::new(ops, txs);
    persist(out, &out_cons, backup_dir, no_backup)?;
    println!("broadcast: {txid}");
    println!("contract: {}", contract_label_of(&out_cons)?);
    println!("bought: {amount}");
    println!(
        "doge_paid: {} (treasury {})",
        koinu_to_doge_string(pay),
        p2pkh_address_from_pkh(network, &treasury)
    );
    Ok(())
}

fn cmd_launch_sell(
    network: Network,
    rpc_url: Option<&str>,
    consignment: &PathBuf,
    amount: &str,
    wif: &str,
    pool_wif: &str,
    pay_wif: Option<&str>,
    out: &PathBuf,
    seal_doge: &str,
    backup_dir: &PathBuf,
    no_backup: bool,
) -> Result<()> {
    let amount: u128 = amount.parse().context("amount must be a u128")?;
    if amount == 0 {
        bail!("sell amount must be > 0");
    }
    let seal_val = parse_doge_to_koinu(seal_doge)?;
    if seal_val < SOFT_DUST_KOINU {
        bail!("--seal-doge must be >= 0.01");
    }
    let (_net, seller_sk, _) = decode_wif(wif)?;
    let pool_sk = decode_wif(pool_wif)?.1;
    let pay_sk = match pay_wif {
        Some(w) => decode_wif(w)?.1,
        None => seller_sk,
    };
    let seller_pk = yard_core::compressed_pubkey(&seller_sk);
    let pool_pk = yard_core::compressed_pubkey(&pool_sk);
    let pay_pk = yard_core::compressed_pubkey(&pay_sk);
    let pay_addr = p2pkh_address(network, &pay_pk);
    let rpc = RpcClient::for_network(network, rpc_url)?;

    let cons = load_consignment(consignment)?;
    let accepted = validate_consignment(&cons)?;
    let genesis = accepted.first().context("no genesis")?;
    let meta = GenesisMeta::from_bytes(&genesis.op.meta)?;
    let spec = meta
        .launch
        .as_ref()
        .context("this contract has no launch spec")?;
    if genesis.op.outputs[0].pubkey != pool_pk {
        bail!("--pool-wif does not match the launch pool pubkey");
    }
    let pool0 = genesis.op.outputs[0].amount;
    let notes = open_notes(&accepted);
    let pool = notes
        .iter()
        .find(|(_, _, pk, _)| *pk == pool_pk)
        .context("no open pool note in this consignment")?;
    let seller = notes
        .iter()
        .find(|(_, _, pk, _)| *pk == seller_pk)
        .context("no open seller note in this consignment for --wif")?;
    let (pool_seal, pool_amt, _, cid) = pool.clone();
    let (seller_seal, seller_amt, _, _) = seller.clone();
    if amount > seller_amt.0 {
        bail!("amount {amount} exceeds seller note {}", seller_amt.0);
    }
    let refund = spec.sell_refund(pool0.0, pool_amt.0, amount)?;
    if refund == 0 {
        bail!("curve refund is 0");
    }
    let pay = relayable_pay(refund)?;
    let seller_pkh = hash160(&seller_pk);

    let mut outputs = vec![OpOutput {
        seal: Outpoint::this_tx(1),
        amount: Amount(pool_amt.0 + amount),
        pubkey: pool_pk,
    }];
    let mut seals = vec![SealOutput {
        value: seal_val,
        pubkey: pool_pk,
    }];
    if amount < seller_amt.0 {
        outputs.push(OpOutput {
            seal: Outpoint::this_tx(2),
            amount: Amount(seller_amt.0 - amount),
            pubkey: seller_pk,
        });
        seals.push(SealOutput {
            value: seal_val,
            pubkey: seller_pk,
        });
    }

    let prev_pool = accepted
        .iter()
        .rev()
        .find(|a| {
            a.op.outputs
                .iter()
                .any(|o| o.seal.resolved(&a.l1_txid) == pool_seal)
        })
        .context("no accepted op created the pool seal")?;
    let prev_seller = accepted
        .iter()
        .rev()
        .find(|a| {
            a.op.outputs
                .iter()
                .any(|o| o.seal.resolved(&a.l1_txid) == seller_seal)
        })
        .context("no accepted op created the seller seal")?;
    let mut sell = Operation {
        op_version: 1,
        contract_id: cid,
        op_type: OpType::LaunchSell,
        inputs: vec![
            OpInput {
                prev_op_hash: prev_pool.op.op_hash()?,
                prev_seal: pool_seal,
                amount: pool_amt,
            },
            OpInput {
                prev_op_hash: prev_seller.op.op_hash()?,
                prev_seal: seller_seal,
                amount: seller_amt,
            },
        ],
        outputs,
        meta: vec![],
        sigs: vec![[0u8; 64], [0u8; 64]],
    };
    sell.sign(0, &pool_sk)?;
    sell.sign(1, &seller_sk)?;
    let cm = Commitment::single(&sell)?;

    let mut spends = vec![
        seal_spend(&rpc, &pool_seal, &pool_sk)?,
        seal_spend(&rpc, &seller_seal, &seller_sk)?,
    ];
    let extra = rpc.listunspent(1, &[pay_addr])?;
    let need: u64 = seals.iter().map(|s| s.value).sum::<u64>() + pay + 2_000_000;
    add_funding(
        &mut spends,
        &extra,
        &pay_sk,
        need,
        &[pool_seal, seller_seal],
    )?;
    let pays = [PayOutput {
        value: pay,
        pkh: seller_pkh,
    }];
    let tx = build_yard_tx_with_pays(&spends, &seals, &pays, Some(hash160(&pay_pk)), &cm)?;
    let hex = hex::encode(tx.encode());
    let txid = rpc.sendrawtransaction(&hex)?;

    let mut ops = cons.ops.clone();
    ops.push(sell);
    let mut txs = cons.txs.clone();
    txs.push(tx);
    let out_cons = Consignment::new(ops, txs);
    persist(out, &out_cons, backup_dir, no_backup)?;
    println!("broadcast: {txid}");
    println!("contract: {}", contract_label_of(&out_cons)?);
    println!("sold: {amount}");
    println!("doge_refund: {}", koinu_to_doge_string(pay));
    Ok(())
}

fn relayable_pay(cost: u128) -> Result<u64> {
    if cost > u64::MAX as u128 {
        bail!("curve cost exceeds u64 koinu");
    }
    let c = cost as u64;
    Ok(c.max(SOFT_DUST_KOINU))
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

fn add_funding(
    spends: &mut Vec<Spendable>,
    extra: &[yard_doge::Utxo],
    sk: &SecretKey,
    need: u64,
    skip: &[Outpoint],
) -> Result<()> {
    let have: u64 = spends.iter().map(|s| s.value).sum();
    if have >= need {
        return Ok(());
    }
    let pk = yard_core::compressed_pubkey(sk);
    let fallback = yard_core::p2pkh_script(&hash160(&pk));
    for u in extra {
        if skip.contains(&u.prevout) {
            continue;
        }
        if spends.iter().any(|s| s.prevout == u.prevout) {
            continue;
        }
        let script = if u.script_hex.is_empty() {
            fallback.clone()
        } else {
            hex::decode(&u.script_hex).unwrap_or_else(|_| fallback.clone())
        };
        spends.push(Spendable {
            prevout: u.prevout,
            value: u.amount_koinu,
            script_pubkey: script,
            secret: *sk,
        });
        if spends.iter().map(|s| s.value).sum::<u64>() >= need {
            return Ok(());
        }
    }
    bail!("insufficient confirmed UTXOs (need about {need} koinu)")
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
