use crate::network::Network;
use crate::Error;
use serde_json::{json, Value};
use yard_core::{rpc_txid_to_internal, Outpoint, Transaction};

#[derive(Clone, Debug)]
pub struct RpcClient {
    url: String,
    user: String,
    pass: String,
    http: reqwest::blocking::Client,
}

#[derive(Clone, Debug)]
pub struct Utxo {
    pub prevout: Outpoint,
    pub amount_koinu: u64,
    pub script_hex: String,
    pub address: Option<String>,
    pub confirmations: u64,
}

impl RpcClient {
    pub fn from_url(url: &str) -> Result<Self, Error> {
        let parsed = reqwest::Url::parse(url).map_err(|e| Error::Rpc(e.to_string()))?;
        let user = parsed.username().to_string();
        let pass = parsed.password().unwrap_or("").to_string();
        let mut clean = parsed.clone();
        let _ = clean.set_username("");
        let _ = clean.set_password(None);
        Ok(Self {
            url: clean.to_string(),
            user,
            pass,
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }

    pub fn for_network(network: Network, override_url: Option<&str>) -> Result<Self, Error> {
        match override_url {
            Some(u) => Self::from_url(u),
            None => Self::from_url(&network.default_rpc_url()),
        }
    }

    pub fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, Error> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "yard",
            "method": method,
            "params": params,
        });
        let resp = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .json(&body)
            .send()?;
        let status = resp.status();
        let v: Value = resp
            .json()
            .map_err(|e| Error::Rpc(format!("invalid json from {method} (http {status}): {e}")))?;
        if let Some(err) = v.get("error") {
            if !err.is_null() {
                return Err(Error::Rpc(format!("{method} error: {err}")));
            }
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }

    pub fn getblockcount(&self) -> Result<u64, Error> {
        let v = self.call("getblockcount", vec![])?;
        v.as_u64()
            .ok_or_else(|| Error::Rpc("getblockcount not a number".into()))
    }

    pub fn getblockhash(&self, height: u64) -> Result<String, Error> {
        let v = self.call("getblockhash", vec![json!(height)])?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Rpc("getblockhash not a string".into()))
    }

    pub fn getblock(&self, hash: &str, verbosity: u64) -> Result<Value, Error> {
        self.call("getblock", vec![json!(hash), json!(verbosity)])
    }

    pub fn getblockchaininfo(&self) -> Result<Value, Error> {
        self.call("getblockchaininfo", vec![])
    }

    pub fn getrawtransaction(&self, txid: &str, verbose: bool) -> Result<Value, Error> {
        self.call("getrawtransaction", vec![json!(txid), json!(verbose)])
    }

    pub fn getrawtransaction_hex(&self, txid: &str) -> Result<String, Error> {
        let v = self.getrawtransaction(txid, false)?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Rpc("getrawtransaction hex missing".into()))
    }

    pub fn getrawtransaction_decoded(&self, txid: &str) -> Result<Value, Error> {
        self.getrawtransaction(txid, true)
    }

    pub fn sendrawtransaction(&self, hex: &str) -> Result<String, Error> {
        let v = self.call("sendrawtransaction", vec![json!(hex)])?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Rpc("sendrawtransaction did not return txid".into()))
    }

    pub fn listunspent(&self, minconf: u64, addresses: &[String]) -> Result<Vec<Utxo>, Error> {
        let mut params = vec![json!(minconf), json!(9999999)];
        if !addresses.is_empty() {
            params.push(json!(addresses));
        }
        let v = self.call("listunspent", params)?;
        let arr = v
            .as_array()
            .ok_or_else(|| Error::Rpc("listunspent not an array".into()))?;
        let mut out = Vec::new();
        for u in arr {
            let txid = u
                .get("txid")
                .and_then(|x| x.as_str())
                .ok_or_else(|| Error::Rpc("utxo missing txid".into()))?;
            let vout =
                u.get("vout")
                    .and_then(|x| x.as_u64())
                    .ok_or_else(|| Error::Rpc("utxo missing vout".into()))? as u32;
            let amount = json_amount_to_koinu(u.get("amount"))?;
            let script_hex = u
                .get("scriptPubKey")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let address = u
                .get("address")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let confirmations = u.get("confirmations").and_then(|x| x.as_u64()).unwrap_or(0);
            out.push(Utxo {
                prevout: Outpoint {
                    txid: rpc_txid_to_internal(txid)?,
                    vout,
                },
                amount_koinu: amount,
                script_hex,
                address,
                confirmations,
            });
        }
        Ok(out)
    }

    /// Regtest only. The secret is never logged.
    pub fn dumpprivkey(&self, address: &str) -> Result<String, Error> {
        let v = self.call("dumpprivkey", vec![json!(address)])?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Rpc("dumpprivkey did not return a WIF".into()))
    }

    pub fn generatetoaddress(&self, n: u64, address: &str) -> Result<Value, Error> {
        self.call("generatetoaddress", vec![json!(n), json!(address)])
    }

    pub fn get_tx_confirmations(&self, rpc_txid: &str) -> Result<Option<u64>, Error> {
        match self.getrawtransaction(rpc_txid, true) {
            Ok(v) => Ok(v.get("confirmations").and_then(|c| c.as_u64())),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("No such mempool") || msg.contains("not found") {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn fetch_tx(&self, rpc_txid: &str) -> Result<Transaction, Error> {
        let hex = self.getrawtransaction_hex(rpc_txid)?;
        let bytes = hex::decode(hex.trim()).map_err(|e| Error::Rpc(e.to_string()))?;
        Ok(Transaction::decode(&bytes)?)
    }
}

/// Core RPC amounts are JSON numbers in whole DOGE. Consensus code never
/// sees this; we only convert at the RPC boundary.
fn json_amount_to_koinu(v: Option<&Value>) -> Result<u64, Error> {
    match v {
        Some(Value::Number(n)) => {
            if let Some(f) = n.as_f64() {
                // Round to nearest koinu. Consensus never sees this conversion.
                let k = (f * 100_000_000.0).round();
                if k < 0.0 || k > u64::MAX as f64 {
                    return Err(Error::Rpc("amount out of range".into()));
                }
                Ok(k as u64)
            } else if let Some(i) = n.as_u64() {
                i.checked_mul(100_000_000)
                    .ok_or_else(|| Error::Rpc("amount overflow".into()))
            } else {
                Err(Error::Rpc("unusable amount number".into()))
            }
        }
        Some(Value::String(s)) => crate::fee::parse_doge_to_koinu(s),
        _ => Err(Error::Rpc("utxo missing amount".into())),
    }
}
