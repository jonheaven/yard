use crate::Error;
use secp256k1::{ecdsa::Signature, Message, PublicKey, SecretKey, SECP256K1};

/// secp256k1 group order / 2. BIP146 low-S means s <= n/2.
const HALF_N: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// Sign SHA256d(message) as compact 64-byte r||s, low-S.
pub fn sign_compact(msg32: &[u8; 32], sk: &SecretKey) -> Result<[u8; 64], Error> {
    let msg = Message::from_digest(*msg32);
    let sig = SECP256K1.sign_ecdsa(&msg, sk);
    let compact = sig.serialize_compact();
    if !is_low_s(&compact) {
        return Err(Error::HighS);
    }
    Ok(compact)
}

/// Verify compact 64-byte r||s. High-S is rejected before the curve check.
pub fn verify_compact(msg32: &[u8; 32], sig: &[u8; 64], pk33: &[u8; 33]) -> Result<(), Error> {
    if !is_low_s(sig) {
        return Err(Error::HighS);
    }
    let signature = Signature::from_compact(sig).map_err(Error::from)?;
    let pk = PublicKey::from_slice(pk33).map_err(Error::from)?;
    let msg = Message::from_digest(*msg32);
    SECP256K1
        .verify_ecdsa(&msg, &signature, &pk)
        .map_err(|_| Error::T5)
}

pub fn is_low_s(sig: &[u8; 64]) -> bool {
    sig[32..] <= HALF_N[..]
}

pub fn compressed_pubkey(sk: &SecretKey) -> [u8; 33] {
    PublicKey::from_secret_key(SECP256K1, sk).serialize()
}

pub fn secret_from_bytes(b: &[u8]) -> Result<SecretKey, Error> {
    SecretKey::from_slice(b).map_err(Error::from)
}

/// secp256k1 spec test scalar 1. Unit tests only — never mainnet funds.
pub fn test_secret() -> SecretKey {
    let mut b = [0u8; 32];
    b[31] = 1;
    SecretKey::from_slice(&b).expect("scalar 1 is a valid secret")
}

/// Negate S (n - s) for the high-S rejection test. Not used on library paths.
pub fn negate_s_for_test(compact: [u8; 64]) -> [u8; 64] {
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let s = &compact[32..];
    let mut out = compact;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = N[i] as i16 - s[i] as i16 - borrow;
        if d < 0 {
            out[32 + i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[32 + i] = d as u8;
            borrow = 0;
        }
    }
    out
}
