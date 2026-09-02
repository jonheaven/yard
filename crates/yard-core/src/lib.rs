//! YARD client-side validation: types, canonical encoding, signatures, rules G1–T8.
//!
//! No network, no RPC, no sqlite.

mod amount;
mod commitment;
mod consignment;
mod error;
mod hash;
mod l1;
mod meta;
mod operation;
mod outpoint;
mod sig;
mod validate;

pub use amount::Amount;
pub use commitment::{merkle_root, Commitment, CommitmentKind, COMMITMENT_LEN};
pub use consignment::{Consignment, MerkleProof, CONS_MAGIC};
pub use error::Error;
pub use hash::{compact_size_len, sha256d, tagged_sha256d, TAG_OP, TAG_SIGHASH};
pub use l1::{
    is_p2pkh, opreturn_script, p2pkh_script, parse_opreturn_payload, Transaction, TxIn, TxOut,
};
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
}
