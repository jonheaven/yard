use crate::network::Network;
use crate::Error;
use bitcoin_hashes::{hash160, Hash};
use secp256k1::SecretKey;
use yard_core::{compressed_pubkey, sha256d};

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn hash160(data: &[u8]) -> [u8; 20] {
    hash160::Hash::hash(data).to_byte_array()
}

pub fn p2pkh_address(network: Network, pubkey33: &[u8; 33]) -> String {
    p2pkh_address_from_pkh(network, &hash160(pubkey33))
}

pub fn p2pkh_address_from_pkh(network: Network, pkh: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(21);
    payload.push(network.p2pkh_version());
    payload.extend_from_slice(pkh);
    check_encode(&payload)
}

pub fn pkh_from_p2pkh_address(addr: &str) -> Result<[u8; 20], Error> {
    let (_ver, payload) = decode_address(addr)?;
    if payload.len() != 20 {
        return Err(Error::Address("not a P2PKH payload".into()));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&payload);
    Ok(a)
}

pub fn decode_address(addr: &str) -> Result<(u8, Vec<u8>), Error> {
    let payload = check_decode(addr)?;
    if payload.is_empty() {
        return Err(Error::Address("empty payload".into()));
    }
    Ok((payload[0], payload[1..].to_vec()))
}

pub fn encode_wif(network: Network, sk: &SecretKey, compressed: bool) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(network.wif_version());
    payload.extend_from_slice(&sk.secret_bytes());
    if compressed {
        payload.push(0x01);
    }
    check_encode(&payload)
}

pub fn decode_wif(wif: &str) -> Result<(Network, SecretKey, bool), Error> {
    let payload = check_decode(wif.trim())?;
    if payload.len() != 33 && payload.len() != 34 {
        return Err(Error::Wif("unexpected WIF length".into()));
    }
    let ver = payload[0];
    let network = match ver {
        0x9e => Network::Mainnet,
        0xf1 => Network::Testnet,
        0xef => Network::Regtest,
        _ => return Err(Error::Wif(format!("unknown WIF version 0x{ver:02x}"))),
    };
    let compressed = payload.len() == 34;
    if compressed && payload[33] != 0x01 {
        return Err(Error::Wif("compressed WIF missing 0x01 suffix".into()));
    }
    let sk = SecretKey::from_slice(&payload[1..33]).map_err(|e| Error::Wif(e.to_string()))?;
    Ok((network, sk, compressed))
}

pub fn address_for_secret(network: Network, sk: &SecretKey) -> String {
    p2pkh_address(network, &compressed_pubkey(sk))
}

fn check_encode(payload: &[u8]) -> String {
    let mut v = payload.to_vec();
    let sum = sha256d(&v);
    v.extend_from_slice(&sum[..4]);
    encode_base58(&v)
}

fn check_decode(s: &str) -> Result<Vec<u8>, Error> {
    let v = decode_base58(s)?;
    if v.len() < 4 {
        return Err(Error::Address("too short for checksum".into()));
    }
    let (payload, sum) = v.split_at(v.len() - 4);
    let expect = sha256d(payload);
    if sum != &expect[..4] {
        return Err(Error::Address("bad Base58Check checksum".into()));
    }
    Ok(payload.to_vec())
}

fn encode_base58(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|b| **b == 0).count();
    let mut n = data.to_vec();
    let mut digits = Vec::new();
    while n.iter().any(|&b| b != 0) {
        let mut rem = 0u16;
        for byte in n.iter_mut() {
            let acc = (rem << 8) | (*byte as u16);
            *byte = (acc / 58) as u8;
            rem = acc % 58;
        }
        digits.push(ALPHABET[rem as usize]);
    }
    digits.reverse();
    let mut out = vec![b'1'; zeros];
    out.extend(digits);
    String::from_utf8(out).expect("base58 alphabet is ascii")
}

fn decode_base58(s: &str) -> Result<Vec<u8>, Error> {
    let zeros = s.chars().take_while(|c| *c == '1').count();
    let mut acc = vec![0u8];
    for c in s.chars() {
        let val = ALPHABET
            .iter()
            .position(|&a| a == c as u8)
            .ok_or_else(|| Error::Address(format!("invalid base58 char {c:?}")))?;
        let mut carry = val as u32;
        for byte in acc.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            acc.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // strip leading zeros in acc (they'll be restored from '1' prefix)
    let start = acc.iter().position(|&b| b != 0).unwrap_or(acc.len());
    let mut out = vec![0u8; zeros];
    out.extend_from_slice(&acc[start..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yard_core::test_secret;

    #[test]
    fn t_test_key_address_frozen() {
        let sk = test_secret();
        let pk = compressed_pubkey(&sk);
        assert_eq!(
            hex::encode(pk),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        let addr = p2pkh_address(Network::Mainnet, &pk);
        // Frozen: version 0x1e + HASH160(compressed G).
        assert_eq!(addr, "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE");
        let (ver, payload) = decode_address(&addr).unwrap();
        assert_eq!(ver, 0x1e);
        assert_eq!(payload.len(), 20);
        let wif = encode_wif(Network::Regtest, &sk, true);
        let (net, sk2, compressed) = decode_wif(&wif).unwrap();
        assert_eq!(net, Network::Regtest);
        assert!(compressed);
        assert_eq!(sk.secret_bytes(), sk2.secret_bytes());
        let rt_addr = p2pkh_address(Network::Regtest, &pk);
        // Core 1.14 regtest P2PKH version 0x6f (m/n), not testnet 0x71.
        let (ver, _) = decode_address(&rt_addr).unwrap();
        assert_eq!(ver, 0x6f);
    }
}
