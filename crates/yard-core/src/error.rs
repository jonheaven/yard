use thiserror::Error;

/// YARD client-side validation and codec errors.
/// Consensus rule ids (G1, T3, ...) match YARD.md section 7.
#[derive(Debug, Error)]
pub enum Error {
    #[error("decode error: {0}")]
    Decode(String),

    #[error("encode error: {0}")]
    Encode(String),

    #[error("invalid ticker (must match ^[A-Z0-9]{{1,8}}$)")]
    TickerInvalid,

    #[error("G1: genesis signature invalid")]
    G1,

    #[error("G2: ContractId mismatch")]
    G2,

    #[error("G3: genesis output sum != meta.max")]
    G3,

    #[error("G4: genesis output seal is not an output of the genesis L1 tx")]
    G4,

    #[error("G5: genesis L1 tx missing a valid YARD commitment to this operation")]
    G5,

    #[error("G6: committing L1 tx lacks required confirmations")]
    G6,

    #[error("T1: transfer input does not refer to a previous accepted operation")]
    T1,

    #[error("T2: input amounts != output amounts + burned")]
    T2,

    #[error("T3: input seal was not spent by the committing L1 tx")]
    T3,

    #[error("T4: output seal is not created by this L1 tx or is below 0.01 DOGE")]
    T4,

    #[error("T5: signature does not verify against the pubkey assigned to the seal")]
    T5,

    #[error("T6: OP_RETURN root does not commit to this operation")]
    T6,

    #[error("T7: seal closed twice")]
    T7,

    #[error("T8: op_type not allowed in Phase 0")]
    T8,

    #[error("high-S ECDSA signature is not allowed")]
    HighS,

    #[error("secp256k1: {0}")]
    Secp(String),

    #[error("genesis meta: {0}")]
    Meta(String),

    #[error("consignment: {0}")]
    Consignment(String),

    #[error("L1 tx: {0}")]
    L1(String),
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::Secp(e.to_string())
    }
}
