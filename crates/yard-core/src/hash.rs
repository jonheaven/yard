use bitcoin_hashes::{hash160, Hash};
use sha2::{Digest, Sha256};

/// SHA256d = SHA256(SHA256(x)), same as Dogecoin.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// SHA256d(tag || msg). Not BIP340 tagged hashing — the spec concatenates
/// the UTF-8 tag bytes directly.
pub fn tagged_sha256d(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(tag.len() + msg.len());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(msg);
    sha256d(&buf)
}

pub const TAG_OP: &[u8] = b"yard/op/v1";
pub const TAG_SIGHASH: &[u8] = b"yard/sighash/v1";

/// HASH160 = RIPEMD160(SHA256(x)). Same as Dogecoin P2PKH.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    hash160::Hash::hash(data).to_byte_array()
}

/// Read helpers. All multi-byte integers little-endian.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn finish(self) -> Result<(), crate::Error> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(crate::Error::Decode(format!(
                "trailing {} bytes",
                self.buf.len() - self.pos
            )))
        }
    }

    pub fn u8(&mut self) -> Result<u8, crate::Error> {
        let b = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| crate::Error::Decode("unexpected eof reading u8".into()))?;
        self.pos += 1;
        Ok(b)
    }

    pub fn u16(&mut self) -> Result<u16, crate::Error> {
        let bytes = self.bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, crate::Error> {
        let bytes = self.bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn u128(&mut self) -> Result<u128, crate::Error> {
        let bytes = self.bytes(16)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(bytes);
        Ok(u128::from_le_bytes(arr))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], crate::Error> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| crate::Error::Decode("overflow".into()))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| crate::Error::Decode(format!("need {n} bytes")))?;
        self.pos = end;
        Ok(slice)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], crate::Error> {
        let s = self.bytes(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }
}

pub fn compact_size_len(n: usize) -> usize {
    if n < 0xfd {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    }
}

pub fn write_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

pub fn read_compact_size(r: &mut Reader<'_>) -> Result<u64, crate::Error> {
    let first = r.u8()?;
    match first {
        n @ 0..=0xfc => Ok(n as u64),
        0xfd => Ok(r.u16()? as u64),
        0xfe => Ok(r.u32()? as u64),
        0xff => {
            let b = r.bytes(8)?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(b);
            Ok(u64::from_le_bytes(arr))
        }
    }
}
