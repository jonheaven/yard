use crate::{Amount, Error};
use serde::{Deserialize, Serialize};

const TICKER_RE: &str = r"^[A-Z0-9]{1,8}$";

/// Genesis metadata. JSON, utf-8, max 512 bytes on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisMeta {
    pub p: String,
    pub v: u32,
    pub ty: String,
    pub tick: String,
    pub name: String,
    pub dec: u32,
    pub max: String,
    pub lim: String,
}

impl GenesisMeta {
    pub fn new_ft(tick: &str, name: &str, dec: u32, max: u128, lim: u128) -> Result<Self, Error> {
        let m = Self {
            p: "yard".into(),
            v: 1,
            ty: "ft".into(),
            tick: tick.to_string(),
            name: name.to_string(),
            dec,
            max: max.to_string(),
            lim: lim.to_string(),
        };
        m.validate()?;
        Ok(m)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let b = serde_json::to_vec(self).map_err(|e| Error::Meta(e.to_string()))?;
        if b.len() > crate::META_MAX {
            return Err(Error::Meta(format!(
                "meta {} bytes exceeds {} ",
                b.len(),
                crate::META_MAX
            )));
        }
        Ok(b)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() > crate::META_MAX {
            return Err(Error::Meta("meta exceeds 512 bytes".into()));
        }
        let m: Self = serde_json::from_slice(b).map_err(|e| Error::Meta(e.to_string()))?;
        m.validate()?;
        Ok(m)
    }

    pub fn max_amount(&self) -> Result<Amount, Error> {
        self.max
            .parse::<u128>()
            .map(Amount)
            .map_err(|_| Error::Meta("max is not a u128 decimal string".into()))
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.p != "yard" {
            return Err(Error::Meta("p must be \"yard\"".into()));
        }
        if self.v != 1 {
            return Err(Error::Meta("v must be 1".into()));
        }
        if self.ty != "ft" && self.ty != "nft" {
            return Err(Error::Meta("ty must be ft or nft".into()));
        }
        validate_ticker(&self.tick)?;
        self.max_amount()?;
        self.lim
            .parse::<u128>()
            .map_err(|_| Error::Meta("lim is not a u128 decimal string".into()))?;
        Ok(())
    }
}

/// Ticker: `^[A-Z0-9]{1,8}$`.
pub fn validate_ticker(tick: &str) -> Result<(), Error> {
    if tick.is_empty() || tick.len() > 8 {
        return Err(Error::TickerInvalid);
    }
    if !tick.chars().all(|c| matches!(c, 'A'..='Z' | '0'..='9')) {
        return Err(Error::TickerInvalid);
    }
    let _ = TICKER_RE;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_ticker_invalid() {
        assert!(validate_ticker("TEST").is_ok());
        assert!(validate_ticker("A").is_ok());
        assert!(validate_ticker("ABCDEFGH").is_ok());
        assert!(validate_ticker("TEST1").is_ok());
        assert_eq!(
            validate_ticker("test").unwrap_err().to_string(),
            Error::TickerInvalid.to_string()
        );
        assert!(validate_ticker("").is_err());
        assert!(validate_ticker("ABCDEFGHI").is_err());
        assert!(validate_ticker("TE-ST").is_err());
    }
}
