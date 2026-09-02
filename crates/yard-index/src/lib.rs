//! Convenience indexer. Finds YARD OP_RETURN commitments. Not a source of truth.

use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;
use yard_core::{parse_opreturn_payload, Commitment, MAGIC_BYTES};
use yard_doge::RpcClient;

#[derive(Debug, Error)]
pub enum Error {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("rpc: {0}")]
    Rpc(#[from] yard_doge::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("core: {0}")]
    Core(#[from] yard_core::Error),
}

pub struct Index {
    db: Connection,
}

#[derive(Clone, Debug)]
pub struct FoundCommit {
    pub txid_rpc: String,
    pub height: i64,
    pub root_hex: String,
    pub raw_hex: String,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS blocks (
    height INTEGER PRIMARY KEY,
    hash TEXT NOT NULL,
    prev TEXT
);
CREATE TABLE IF NOT EXISTS commits (
    txid TEXT PRIMARY KEY,
    height INTEGER,
    root BLOB,
    raw BLOB
);
CREATE TABLE IF NOT EXISTS ops (
    op_hash TEXT PRIMARY KEY,
    contract TEXT,
    raw BLOB,
    txid TEXT
);
CREATE TABLE IF NOT EXISTS seals (
    outpoint TEXT PRIMARY KEY,
    contract TEXT,
    amount TEXT,
    pubkey BLOB,
    op_hash TEXT,
    spent_by TEXT NULL
);
CREATE TABLE IF NOT EXISTS reorgs (
    id INTEGER PRIMARY KEY,
    from_height INTEGER,
    note TEXT
);
"#;

impl Index {
    pub fn open(path: &str) -> Result<Self, Error> {
        let db = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };
        db.execute_batch(SCHEMA)?;
        Ok(Self { db })
    }

    pub fn tip_height(&self) -> Result<Option<i64>, Error> {
        let h: Option<i64> = self
            .db
            .query_row("SELECT MAX(height) FROM blocks", [], |r| r.get(0))?;
        Ok(h)
    }

    /// Scan `[from, tip]` for OP_RETURN payloads starting with magic YARD.
    /// Does not accept operations from the chain — consignments remain the
    /// source of note state.
    pub fn sync(&mut self, rpc: &RpcClient, from: u64) -> Result<Vec<FoundCommit>, Error> {
        let tip = rpc.getblockcount()?;
        let start = from;
        let mut found = Vec::new();
        let mut prev_hash = String::new();
        if start > 0 {
            if let Ok(h) = rpc.getblockhash(start - 1) {
                prev_hash = h;
            }
        }

        for height in start..=tip {
            let hash = rpc.getblockhash(height)?;
            // Reorg: stored hash at this height differs.
            if let Ok(Some(stored)) = self.hash_at(height as i64) {
                if stored != hash {
                    self.rewind(height as i64, &format!("reorg at {height}"))?;
                }
            }
            let block = rpc.getblock(&hash, 2)?;
            self.db.execute(
                "INSERT OR REPLACE INTO blocks (height, hash, prev) VALUES (?1, ?2, ?3)",
                params![height as i64, hash, prev_hash],
            )?;
            prev_hash = hash.clone();

            let txs = match block.get("tx").and_then(|t| t.as_array()) {
                Some(a) => a.clone(),
                None => continue,
            };
            for tx in txs {
                let txid = match tx.get("txid").and_then(|x| x.as_str()) {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                let vouts = match tx.get("vout").and_then(|x| x.as_array()) {
                    Some(v) => v,
                    None => continue,
                };
                for vout in vouts {
                    let script_hex = vout
                        .pointer("/scriptPubKey/hex")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    if script_hex.is_empty() {
                        continue;
                    }
                    let script = match hex::decode(script_hex) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let payload = match parse_opreturn_payload(&script) {
                        Ok(Some(p)) => p,
                        _ => continue,
                    };
                    if !payload.starts_with(&MAGIC_BYTES) {
                        continue;
                    }
                    let cm = match Commitment::decode(&payload) {
                        Ok(c) => c,
                        Err(_) => continue, // indexer stores only well-formed v1
                    };
                    self.db.execute(
                        "INSERT OR REPLACE INTO commits (txid, height, root, raw) VALUES (?1, ?2, ?3, ?4)",
                        params![txid, height as i64, cm.root.as_slice(), payload.as_slice()],
                    )?;
                    found.push(FoundCommit {
                        txid_rpc: txid.clone(),
                        height: height as i64,
                        root_hex: hex::encode(cm.root),
                        raw_hex: hex::encode(&payload),
                    });
                }
            }
        }
        Ok(found)
    }

    pub fn hash_at(&self, height: i64) -> Result<Option<String>, Error> {
        let h = self
            .db
            .query_row(
                "SELECT hash FROM blocks WHERE height = ?1",
                params![height],
                |r| r.get(0),
            )
            .optional()?;
        Ok(h)
    }

    pub fn rewind(&mut self, from_height: i64, note: &str) -> Result<(), Error> {
        self.db.execute(
            "INSERT INTO reorgs (from_height, note) VALUES (?1, ?2)",
            params![from_height, note],
        )?;
        self.db.execute(
            "DELETE FROM commits WHERE height >= ?1",
            params![from_height],
        )?;
        self.db.execute(
            "DELETE FROM blocks WHERE height >= ?1",
            params![from_height],
        )?;
        Ok(())
    }

    pub fn commits(&self) -> Result<Vec<FoundCommit>, Error> {
        let mut stmt = self
            .db
            .prepare("SELECT txid, height, root, raw FROM commits ORDER BY height")?;
        let rows = stmt.query_map([], |r| {
            let root: Vec<u8> = r.get(2)?;
            let raw: Vec<u8> = r.get(3)?;
            Ok(FoundCommit {
                txid_rpc: r.get(0)?,
                height: r.get(1)?,
                root_hex: hex::encode(root),
                raw_hex: hex::encode(raw),
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Optional: persist a locally validated operation. Still not a source of
    /// truth for anyone else.
    pub fn store_op(
        &self,
        op_hash: &str,
        contract: &str,
        raw: &[u8],
        txid: &str,
    ) -> Result<(), Error> {
        self.db.execute(
            "INSERT OR REPLACE INTO ops (op_hash, contract, raw, txid) VALUES (?1, ?2, ?3, ?4)",
            params![op_hash, contract, raw, txid],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_schema_opens() {
        let idx = Index::open(":memory:").unwrap();
        assert!(idx.tip_height().unwrap().is_none());
        idx.store_op("aa", "bb", &[1, 2, 3], "cc").unwrap();
    }
}
