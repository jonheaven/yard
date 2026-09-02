//! YARD client-side validation: types, canonical encoding, signatures, rules G1–T8.
//!
//! No network, no RPC, no sqlite.

mod amount;
mod commitment;
mod consignment;
mod error;
mod hash;
mod l1;
mod launch;
mod meta;
mod operation;
mod outpoint;
mod sig;
mod validate;

pub use amount::Amount;
pub use commitment::{merkle_root, Commitment, CommitmentKind, COMMITMENT_LEN};
pub use consignment::{Consignment, MerkleProof, CONS_MAGIC};
pub use error::Error;
pub use hash::{compact_size_len, hash160, sha256d, tagged_sha256d, TAG_OP, TAG_SIGHASH};
pub use l1::{
    is_p2pkh, opreturn_script, p2pkh_script, parse_opreturn_payload, Transaction, TxIn, TxOut,
};
pub use launch::{cpmm_buy_cost, cpmm_sell_refund, cpmm_x, linear_buy_cost, LaunchSpec};
pub use meta::{validate_ticker, GenesisMeta};
pub use operation::{OpInput, OpOutput, OpType, Operation};
pub use outpoint::{
    hex_internal, rpc_hex, rpc_txid_to_internal, ContractId, Magic, Outpoint, Seal, MAGIC_BYTES,
};
pub use sig::{
    compressed_pubkey, is_low_s, negate_s_for_test, secret_from_bytes, sign_compact, test_secret,
    verify_compact,
};
pub use validate::{open_notes, validate_consignment, validate_operation, AcceptedOp};

/// 1 DOGE = 100_000_000 koinu.
pub const KOINU_PER_DOGE: u64 = 100_000_000;
/// Soft dust / minimum seal UTXO (0.01 DOGE).
pub const SOFT_DUST_KOINU: u64 = 1_000_000;
/// Hard dust (0.001 DOGE).
pub const HARD_DUST_KOINU: u64 = 100_000;
/// Preferred seal value (0.05 DOGE).
pub const PREFERRED_SEAL_KOINU: u64 = 5_000_000;
/// Recommended fee: 0.01 DOGE per started kilobyte.
pub const FEE_PER_KB_KOINU: u64 = 1_000_000;
pub const META_MAX: usize = 512;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1::p2pkh_script;

    fn dummy_pkh() -> [u8; 20] {
        [0x11; 20]
    }

    fn genesis_meta_bytes(max: u128) -> Vec<u8> {
        GenesisMeta::new_ft("TEST", "Test Note", 8, max, 0)
            .unwrap()
            .to_bytes()
            .unwrap()
    }

    fn signed_genesis(vout: u32, amount: u128) -> Operation {
        let pk = compressed_pubkey(&test_secret());
        let mut op = Operation {
            op_version: 1,
            contract_id: ContractId::zeros(),
            op_type: OpType::Genesis,
            inputs: vec![],
            outputs: vec![OpOutput {
                seal: Outpoint::this_tx(vout),
                amount: Amount(amount),
                pubkey: pk,
            }],
            meta: genesis_meta_bytes(amount),
            sigs: vec![[0u8; 64]],
        };
        op.sign(0, &test_secret()).unwrap();
        op
    }

    fn l1_for_genesis(op: &Operation, seal_vout: u32, seal_value: u64) -> Transaction {
        let cm = Commitment::single(op).unwrap();
        let mut vout = vec![TxOut {
            value: 0,
            script_pubkey: opreturn_script(&cm.encode()).unwrap(),
        }];
        while vout.len() <= seal_vout as usize {
            vout.push(TxOut {
                value: seal_value,
                script_pubkey: p2pkh_script(&dummy_pkh()),
            });
        }
        Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: Outpoint {
                    txid: [0x22; 32],
                    vout: 0,
                },
                script_sig: vec![0x00],
                sequence: 0xffffffff,
            }],
            vout,
            lock_time: 0,
        }
    }

    #[test]
    fn t_magic_bytes() {
        assert_eq!(&MAGIC_BYTES, b"YARD");
        assert_eq!(MAGIC_BYTES, [0x59, 0x41, 0x52, 0x44]);
        assert_eq!(Magic::bytes(), MAGIC_BYTES);
    }

    #[test]
    fn t_commitment_payload_is_40_bytes() {
        let op = signed_genesis(1, 21_000_000_000_000_000);
        let cm = Commitment::single(&op).unwrap();
        let bytes = cm.encode();
        assert_eq!(bytes.len(), 40);
        assert_eq!(COMMITMENT_LEN, 40);
        let decoded = Commitment::decode(&bytes).unwrap();
        assert_eq!(decoded, cm);
        // extra trailing byte rejected
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(Commitment::decode(&extra).is_err());
    }

    #[test]
    fn t_genesis_roundtrip() {
        let op = signed_genesis(1, 21_000_000_000_000_000);
        let bytes = op.encode().unwrap();
        let op2 = Operation::decode(&bytes).unwrap();
        assert_eq!(op, op2);
        op.verify_sig(0, &op.outputs[0].pubkey).unwrap();
        let tx = l1_for_genesis(&op, 1, SOFT_DUST_KOINU);
        validate_operation(&op, &[], &tx, std::slice::from_ref(&op)).unwrap();
        let cid = op.genesis_contract_id().unwrap();
        assert_ne!(cid.0, [0u8; 32]);
    }

    #[test]
    fn t_transfer_balances() {
        let genesis = signed_genesis(1, 1_000);
        let gtx = l1_for_genesis(&genesis, 1, SOFT_DUST_KOINU);
        validate_operation(&genesis, &[], &gtx, std::slice::from_ref(&genesis)).unwrap();
        let accepted = AcceptedOp {
            op: genesis.clone(),
            l1_txid: gtx.txid(),
            contract_id: genesis.genesis_contract_id().unwrap(),
        };
        let pk = compressed_pubkey(&test_secret());
        let spent = Outpoint {
            txid: gtx.txid(),
            vout: 1,
        };
        let mut xfer = Operation {
            op_version: 1,
            contract_id: accepted.contract_id,
            op_type: OpType::Transfer,
            inputs: vec![OpInput {
                prev_op_hash: genesis.op_hash().unwrap(),
                prev_seal: spent,
                amount: Amount(1_000),
            }],
            outputs: vec![
                OpOutput {
                    seal: Outpoint::this_tx(1),
                    amount: Amount(400),
                    pubkey: pk,
                },
                OpOutput {
                    seal: Outpoint::this_tx(2),
                    amount: Amount(600),
                    pubkey: pk,
                },
            ],
            meta: vec![],
            sigs: vec![[0u8; 64]],
        };
        xfer.sign(0, &test_secret()).unwrap();
        let cm = Commitment::single(&xfer).unwrap();
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: spent,
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
                    script_pubkey: p2pkh_script(&dummy_pkh()),
                },
                TxOut {
                    value: SOFT_DUST_KOINU,
                    script_pubkey: p2pkh_script(&dummy_pkh()),
                },
            ],
            lock_time: 0,
        };
        validate_operation(&xfer, &[accepted], &tx, std::slice::from_ref(&xfer)).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/vectors/transfer.json")).unwrap();
        assert_eq!(
            hex::encode(xfer.encode().unwrap()),
            v["transfer_op_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(genesis.encode().unwrap()),
            v["genesis_op_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn t_reject_inflation() {
        let genesis = signed_genesis(1, 1_000);
        let gtx = l1_for_genesis(&genesis, 1, SOFT_DUST_KOINU);
        let accepted = AcceptedOp {
            op: genesis.clone(),
            l1_txid: gtx.txid(),
            contract_id: genesis.genesis_contract_id().unwrap(),
        };
        let pk = compressed_pubkey(&test_secret());
        let spent = Outpoint {
            txid: gtx.txid(),
            vout: 1,
        };
        let mut xfer = Operation {
            op_version: 1,
            contract_id: accepted.contract_id,
            op_type: OpType::Transfer,
            inputs: vec![OpInput {
                prev_op_hash: genesis.op_hash().unwrap(),
                prev_seal: spent,
                amount: Amount(1_000),
            }],
            outputs: vec![OpOutput {
                seal: Outpoint::this_tx(1),
                amount: Amount(1_001),
                pubkey: pk,
            }],
            meta: vec![],
            sigs: vec![[0u8; 64]],
        };
        xfer.sign(0, &test_secret()).unwrap();
        let cm = Commitment::single(&xfer).unwrap();
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: spent,
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
                    script_pubkey: p2pkh_script(&dummy_pkh()),
                },
            ],
            lock_time: 0,
        };
        let err =
            validate_operation(&xfer, &[accepted], &tx, std::slice::from_ref(&xfer)).unwrap_err();
        assert!(matches!(err, Error::T2), "got {err}");
    }

    #[test]
    fn t_reject_high_s_signature() {
        let mut op = signed_genesis(1, 21_000_000_000_000_000);
        op.sigs[0] = negate_s_for_test(op.sigs[0]);
        assert!(!is_low_s(&op.sigs[0]));
        let err = op.verify_sig(0, &op.outputs[0].pubkey).unwrap_err();
        assert!(matches!(err, Error::HighS), "got {err}");
        let tx = l1_for_genesis(&op, 1, SOFT_DUST_KOINU);
        // commitment is over signed bytes, so this also fails G5/G1 depending on order.
        // Rebuild commitment to isolate HighS/G1.
        let cm = Commitment::single(&op).unwrap();
        let tx = Transaction {
            version: 1,
            vin: tx.vin,
            vout: vec![
                TxOut {
                    value: 0,
                    script_pubkey: opreturn_script(&cm.encode()).unwrap(),
                },
                tx.vout[1].clone(),
            ],
            lock_time: 0,
        };
        let err = validate_operation(&op, &[], &tx, std::slice::from_ref(&op)).unwrap_err();
        assert!(matches!(err, Error::G1 | Error::HighS), "got {err}");
    }

    #[test]
    fn t_reject_wrong_root() {
        let op = signed_genesis(1, 21_000_000_000_000_000);
        let mut cm = Commitment::single(&op).unwrap();
        cm.root[0] ^= 0xff;
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
                    script_pubkey: p2pkh_script(&dummy_pkh()),
                },
            ],
            lock_time: 0,
        };
        let err = validate_operation(&op, &[], &tx, std::slice::from_ref(&op)).unwrap_err();
        assert!(matches!(err, Error::G5 | Error::T6), "got {err}");
    }

    #[test]
    fn t_reject_seal_not_in_tx() {
        let op = signed_genesis(1, 21_000_000_000_000_000);
        // L1 tx has OP_RETURN only — no seal output at vout 1.
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
            vout: vec![TxOut {
                value: 0,
                script_pubkey: opreturn_script(&cm.encode()).unwrap(),
            }],
            lock_time: 0,
        };
        let err = validate_operation(&op, &[], &tx, std::slice::from_ref(&op)).unwrap_err();
        assert!(matches!(err, Error::G4 | Error::T4), "got {err}");
    }

    #[test]
    fn t_contract_id_stable() {
        let op = signed_genesis(1, 21_000_000_000_000_000);
        let cid = op.genesis_contract_id().unwrap();
        let again = Operation::decode(&op.encode().unwrap())
            .unwrap()
            .genesis_contract_id()
            .unwrap();
        assert_eq!(cid, again);
        // G2: ContractId is SHA256d of the full genesis bytes.
        assert_eq!(cid.0, sha256d(&op.encode().unwrap()));
        let raw = include_str!("../../../tests/vectors/genesis.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(cid.to_hex(), v["contract_id"].as_str().unwrap());
        assert_eq!(
            hex::encode(op.encode().unwrap()),
            v["genesis_op_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(compressed_pubkey(&test_secret())),
            v["pubkey_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(Commitment::single(&op).unwrap().encode()),
            v["commitment_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn t_outpoint_rpc_hex_reversed() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        txid[31] = 0xcd;
        let op = Outpoint { txid, vout: 7 };
        let rpc = op.txid_rpc_hex();
        assert!(rpc.starts_with("cd"));
        assert!(rpc.ends_with("ab"));
        let parsed = Outpoint::from_rpc(&rpc, 7).unwrap();
        assert_eq!(parsed, op);
    }

    #[test]
    fn t_reject_tampered_consignment() {
        let genesis = signed_genesis(1, 21_000_000_000_000_000);
        let gtx = l1_for_genesis(&genesis, 1, SOFT_DUST_KOINU);
        let c = Consignment::new(vec![genesis.clone()], vec![gtx.clone()]);
        validate_consignment(&c).unwrap();
        let mut bytes = c.encode_binary().unwrap();
        // Flip a byte in the operation region (after magic+version+n_ops+len).
        let flip = CONS_MAGIC.len() + 1 + 4 + 4 + 10;
        bytes[flip] ^= 0xff;
        let tampered = Consignment::decode_binary(&bytes);
        match tampered {
            Ok(c2) => assert!(validate_consignment(&c2).is_err()),
            Err(_) => {}
        }
    }

    #[test]
    fn t_genesis_g3_max_mismatch() {
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
            meta: genesis_meta_bytes(21_000_000_000_000_000),
            sigs: vec![[0u8; 64]],
        };
        op.sign(0, &test_secret()).unwrap();
        let tx = l1_for_genesis(&op, 1, SOFT_DUST_KOINU);
        let err = validate_operation(&op, &[], &tx, std::slice::from_ref(&op)).unwrap_err();
        assert!(matches!(err, Error::G3), "got {err}");
    }

    #[test]
    fn t_display_tick_never_bare() {
        let op = signed_genesis(1, 21_000_000_000_000_000);
        let cid = op.genesis_contract_id().unwrap();
        let shown = cid.display_with_tick("TEST");
        assert!(shown.starts_with("TEST-"));
        assert_eq!(shown.len(), "TEST-".len() + 8);
        assert_ne!(shown, "TEST");
    }

    #[test]
    fn t_burn_reduces_supply() {
        let genesis = signed_genesis(1, 1_000);
        let gtx = l1_for_genesis(&genesis, 1, SOFT_DUST_KOINU);
        validate_operation(&genesis, &[], &gtx, std::slice::from_ref(&genesis)).unwrap();
        let accepted = AcceptedOp {
            op: genesis.clone(),
            l1_txid: gtx.txid(),
            contract_id: genesis.genesis_contract_id().unwrap(),
        };
        let pk = compressed_pubkey(&test_secret());
        let spent = Outpoint {
            txid: gtx.txid(),
            vout: 1,
        };
        let mut burn = Operation {
            op_version: 1,
            contract_id: accepted.contract_id,
            op_type: OpType::Burn,
            inputs: vec![OpInput {
                prev_op_hash: genesis.op_hash().unwrap(),
                prev_seal: spent,
                amount: Amount(1_000),
            }],
            outputs: vec![OpOutput {
                seal: Outpoint::this_tx(1),
                amount: Amount(700),
                pubkey: pk,
            }],
            meta: vec![],
            sigs: vec![[0u8; 64]],
        };
        burn.sign(0, &test_secret()).unwrap();
        let cm = Commitment::single(&burn).unwrap();
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: spent,
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
                    script_pubkey: p2pkh_script(&dummy_pkh()),
                },
            ],
            lock_time: 0,
        };
        validate_operation(&burn, &[accepted.clone()], &tx, std::slice::from_ref(&burn)).unwrap();
        let cons = Consignment::new(vec![genesis, burn], vec![gtx, tx]);
        let acc = validate_consignment(&cons).unwrap();
        let notes = open_notes(&acc);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].1, Amount(700));
    }

    fn secret_n(n: u8) -> secp256k1::SecretKey {
        let mut b = [0u8; 32];
        b[31] = n;
        secret_from_bytes(&b).unwrap()
    }

    fn genesis_launch(pool_amt: u128, base: u128) -> (Operation, Transaction, [u8; 20]) {
        let pk = compressed_pubkey(&test_secret());
        let treasury = [0xab; 20];
        let mut meta = GenesisMeta::new_ft("MEME", "Meme", 8, pool_amt, 0).unwrap();
        meta.launch = Some(LaunchSpec::linear(&treasury, base, 0).unwrap());
        let mut op = Operation {
            op_version: 1,
            contract_id: ContractId::zeros(),
            op_type: OpType::Genesis,
            inputs: vec![],
            outputs: vec![OpOutput {
                seal: Outpoint::this_tx(1),
                amount: Amount(pool_amt),
                pubkey: pk,
            }],
            meta: meta.to_bytes().unwrap(),
            sigs: vec![[0u8; 64]],
        };
        op.sign(0, &test_secret()).unwrap();
        let tx = l1_for_genesis(&op, 1, SOFT_DUST_KOINU);
        (op, tx, treasury)
    }

    #[test]
    fn t_launch_buy_requires_l1_doge() {
        let (genesis, gtx, treasury) = genesis_launch(1_000, 1_000);
        validate_operation(&genesis, &[], &gtx, std::slice::from_ref(&genesis)).unwrap();
        let accepted = AcceptedOp {
            op: genesis.clone(),
            l1_txid: gtx.txid(),
            contract_id: genesis.genesis_contract_id().unwrap(),
        };
        let pool_pk = compressed_pubkey(&test_secret());
        let buyer_pk = compressed_pubkey(&secret_n(2));
        let spent = Outpoint {
            txid: gtx.txid(),
            vout: 1,
        };
        let mut buy = Operation {
            op_version: 1,
            contract_id: accepted.contract_id,
            op_type: OpType::LaunchBuy,
            inputs: vec![OpInput {
                prev_op_hash: genesis.op_hash().unwrap(),
                prev_seal: spent,
                amount: Amount(1_000),
            }],
            outputs: vec![
                OpOutput {
                    seal: Outpoint::this_tx(1),
                    amount: Amount(10),
                    pubkey: buyer_pk,
                },
                OpOutput {
                    seal: Outpoint::this_tx(2),
                    amount: Amount(990),
                    pubkey: pool_pk,
                },
            ],
            meta: vec![],
            sigs: vec![[0u8; 64]],
        };
        buy.sign(0, &test_secret()).unwrap();
        let cm = Commitment::single(&buy).unwrap();
        let mut tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: spent,
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
                    script_pubkey: p2pkh_script(&hash160(&buyer_pk)),
                },
                TxOut {
                    value: SOFT_DUST_KOINU,
                    script_pubkey: p2pkh_script(&hash160(&pool_pk)),
                },
            ],
            lock_time: 0,
        };
        let err = validate_operation(&buy, &[accepted.clone()], &tx, std::slice::from_ref(&buy))
            .unwrap_err();
        assert!(matches!(err, Error::LaunchPay), "got {err}");
        tx.vout.push(TxOut {
            value: 10_000, // 10 units * 1000 koinu
            script_pubkey: p2pkh_script(&treasury),
        });
        validate_operation(&buy, &[accepted], &tx, std::slice::from_ref(&buy)).unwrap();
    }

    #[test]
    fn t_launch_pool_cannot_transfer() {
        let (genesis, gtx, _) = genesis_launch(1_000, 1_000);
        validate_operation(&genesis, &[], &gtx, std::slice::from_ref(&genesis)).unwrap();
        let accepted = AcceptedOp {
            op: genesis.clone(),
            l1_txid: gtx.txid(),
            contract_id: genesis.genesis_contract_id().unwrap(),
        };
        let pk = compressed_pubkey(&test_secret());
        let spent = Outpoint {
            txid: gtx.txid(),
            vout: 1,
        };
        let mut xfer = Operation {
            op_version: 1,
            contract_id: accepted.contract_id,
            op_type: OpType::Transfer,
            inputs: vec![OpInput {
                prev_op_hash: genesis.op_hash().unwrap(),
                prev_seal: spent,
                amount: Amount(1_000),
            }],
            outputs: vec![OpOutput {
                seal: Outpoint::this_tx(1),
                amount: Amount(1_000),
                pubkey: pk,
            }],
            meta: vec![],
            sigs: vec![[0u8; 64]],
        };
        xfer.sign(0, &test_secret()).unwrap();
        let cm = Commitment::single(&xfer).unwrap();
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: spent,
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
                    script_pubkey: p2pkh_script(&dummy_pkh()),
                },
            ],
            lock_time: 0,
        };
        let err =
            validate_operation(&xfer, &[accepted], &tx, std::slice::from_ref(&xfer)).unwrap_err();
        assert!(matches!(err, Error::T8), "got {err}");
    }

    #[test]
    fn t_burn_all_allows_zero_outputs() {
        let genesis = signed_genesis(1, 1_000);
        let gtx = l1_for_genesis(&genesis, 1, SOFT_DUST_KOINU);
        let accepted = AcceptedOp {
            op: genesis.clone(),
            l1_txid: gtx.txid(),
            contract_id: genesis.genesis_contract_id().unwrap(),
        };
        let spent = Outpoint {
            txid: gtx.txid(),
            vout: 1,
        };
        let mut burn = Operation {
            op_version: 1,
            contract_id: accepted.contract_id,
            op_type: OpType::Burn,
            inputs: vec![OpInput {
                prev_op_hash: genesis.op_hash().unwrap(),
                prev_seal: spent,
                amount: Amount(1_000),
            }],
            outputs: vec![],
            meta: vec![],
            sigs: vec![[0u8; 64]],
        };
        burn.sign(0, &test_secret()).unwrap();
        let cm = Commitment::single(&burn).unwrap();
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: spent,
                script_sig: vec![0x00],
                sequence: 0xffffffff,
            }],
            vout: vec![TxOut {
                value: 0,
                script_pubkey: opreturn_script(&cm.encode()).unwrap(),
            }],
            lock_time: 0,
        };
        validate_operation(&burn, &[accepted], &tx, std::slice::from_ref(&burn)).unwrap();
    }

    #[test]
    fn t_launch_sell_refunds_l1_doge() {
        let (genesis, gtx, treasury) = genesis_launch(1_000, 1_000);
        let g_acc = AcceptedOp {
            op: genesis.clone(),
            l1_txid: gtx.txid(),
            contract_id: genesis.genesis_contract_id().unwrap(),
        };
        let pool_pk = compressed_pubkey(&test_secret());
        let buyer_sk = secret_n(2);
        let buyer_pk = compressed_pubkey(&buyer_sk);
        let pool_spent = Outpoint {
            txid: gtx.txid(),
            vout: 1,
        };
        let mut buy = Operation {
            op_version: 1,
            contract_id: g_acc.contract_id,
            op_type: OpType::LaunchBuy,
            inputs: vec![OpInput {
                prev_op_hash: genesis.op_hash().unwrap(),
                prev_seal: pool_spent,
                amount: Amount(1_000),
            }],
            outputs: vec![
                OpOutput {
                    seal: Outpoint::this_tx(1),
                    amount: Amount(10),
                    pubkey: buyer_pk,
                },
                OpOutput {
                    seal: Outpoint::this_tx(2),
                    amount: Amount(990),
                    pubkey: pool_pk,
                },
            ],
            meta: vec![],
            sigs: vec![[0u8; 64]],
        };
        buy.sign(0, &test_secret()).unwrap();
        let cm = Commitment::single(&buy).unwrap();
        let buy_tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: pool_spent,
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
                    script_pubkey: p2pkh_script(&hash160(&buyer_pk)),
                },
                TxOut {
                    value: SOFT_DUST_KOINU,
                    script_pubkey: p2pkh_script(&hash160(&pool_pk)),
                },
                TxOut {
                    value: 10_000,
                    script_pubkey: p2pkh_script(&treasury),
                },
            ],
            lock_time: 0,
        };
        validate_operation(&buy, &[g_acc.clone()], &buy_tx, std::slice::from_ref(&buy)).unwrap();
        let buy_acc = AcceptedOp {
            op: buy.clone(),
            l1_txid: buy_tx.txid(),
            contract_id: g_acc.contract_id,
        };
        let seller_seal = Outpoint {
            txid: buy_tx.txid(),
            vout: 1,
        };
        let pool_seal = Outpoint {
            txid: buy_tx.txid(),
            vout: 2,
        };
        let mut sell = Operation {
            op_version: 1,
            contract_id: g_acc.contract_id,
            op_type: OpType::LaunchSell,
            inputs: vec![
                OpInput {
                    prev_op_hash: buy.op_hash().unwrap(),
                    prev_seal: pool_seal,
                    amount: Amount(990),
                },
                OpInput {
                    prev_op_hash: buy.op_hash().unwrap(),
                    prev_seal: seller_seal,
                    amount: Amount(10),
                },
            ],
            outputs: vec![OpOutput {
                seal: Outpoint::this_tx(1),
                amount: Amount(1_000),
                pubkey: pool_pk,
            }],
            meta: vec![],
            sigs: vec![[0u8; 64], [0u8; 64]],
        };
        sell.sign(0, &test_secret()).unwrap();
        sell.sign(1, &buyer_sk).unwrap();
        let cm = Commitment::single(&sell).unwrap();
        let sell_tx = Transaction {
            version: 1,
            vin: vec![
                TxIn {
                    prevout: pool_seal,
                    script_sig: vec![0x00],
                    sequence: 0xffffffff,
                },
                TxIn {
                    prevout: seller_seal,
                    script_sig: vec![0x00],
                    sequence: 0xffffffff,
                },
            ],
            vout: vec![
                TxOut {
                    value: 0,
                    script_pubkey: opreturn_script(&cm.encode()).unwrap(),
                },
                TxOut {
                    value: SOFT_DUST_KOINU,
                    script_pubkey: p2pkh_script(&hash160(&pool_pk)),
                },
                TxOut {
                    value: 10_000,
                    script_pubkey: p2pkh_script(&hash160(&buyer_pk)),
                },
            ],
            lock_time: 0,
        };
        validate_operation(
            &sell,
            &[g_acc, buy_acc],
            &sell_tx,
            std::slice::from_ref(&sell),
        )
        .unwrap();
    }
}
