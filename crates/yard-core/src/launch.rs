//! Phase 1 launch notes: a coordinated sale paid in L1 DOGE.
//!
//! Not an AMM. Not miner-enforced. Genesis output[0] is client-validated
//! inventory. Buys and sells must spend that pool seal. The raise is an
//! ordinary P2PKH payment to the treasury hash in the same committing
//! transaction — not wrapped DOGE, not a VM, not a covenant.
//!
//! Sell refunds are also L1 DOGE. Anyone may fund them. A published pool
//! key can be grief-spent as plain DOGE (the 0.05 dust seal dies;
//! already-sold notes remain). Same class of risk as losing a consignment.
//! Do not call this a trustless pool.

use crate::Error;
use serde::{Deserialize, Serialize};

/// Compact genesis-meta object. Keys are short so the 512-byte cap still fits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchSpec {
    /// `lin` (price = base + slope * i) or `cpmm` (constant product).
    pub curve: String,
    /// Treasury HASH160 as 40-char lowercase hex. Raise is paid here on L1.
    pub tr: String,
    /// Linear: koinu per unit at sold=0. Ignored for cpmm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// Linear: extra koinu per unit per unit already sold. Default 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slope: Option<String>,
    /// CPMM: initial virtual DOGE reserve in koinu (`x` in x*y=k).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
}

impl LaunchSpec {
    pub fn linear(treasury_pkh: &[u8; 20], base: u128, slope: u128) -> Result<Self, Error> {
        let s = Self {
            curve: "lin".into(),
            tr: hex::encode(treasury_pkh),
            base: Some(base.to_string()),
            slope: Some(slope.to_string()),
            x: None,
        };
        s.validate()?;
        Ok(s)
    }

    pub fn cpmm(treasury_pkh: &[u8; 20], x: u128) -> Result<Self, Error> {
        let s = Self {
            curve: "cpmm".into(),
            tr: hex::encode(treasury_pkh),
            base: None,
            slope: None,
            x: Some(x.to_string()),
        };
        s.validate()?;
        Ok(s)
    }

    pub fn treasury_pkh(&self) -> Result<[u8; 20], Error> {
        let b = hex::decode(self.tr.trim()).map_err(|e| Error::Meta(e.to_string()))?;
        if b.len() != 20 {
            return Err(Error::Meta("launch.tr must be 20-byte HASH160 hex".into()));
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(&b);
        Ok(a)
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.treasury_pkh()?;
        match self.curve.as_str() {
            "lin" => {
                let base = parse_u128(self.base.as_deref().unwrap_or("0"), "base")?;
                let slope = parse_u128(self.slope.as_deref().unwrap_or("0"), "slope")?;
                if base == 0 && slope == 0 {
                    return Err(Error::Meta(
                        "linear launch needs base > 0 or slope > 0".into(),
                    ));
                }
                Ok(())
            }
            "cpmm" => {
                let x = parse_u128(self.x.as_deref().unwrap_or("0"), "x")?;
                if x == 0 {
                    return Err(Error::Meta("cpmm launch needs x (doge reserve) > 0".into()));
                }
                Ok(())
            }
            other => Err(Error::Meta(format!(
                "launch.curve must be lin or cpmm, got {other:?}"
            ))),
        }
    }

    /// Koinu the buyer must pay to treasury to take `n` units when `sold`
    /// units have already left the pool.
    ///
    /// `pool0` is genesis output[0] amount. `pool_in` is the pool note being spent.
    pub fn buy_cost(&self, pool0: u128, pool_in: u128, n: u128) -> Result<u128, Error> {
        if n == 0 {
            return Err(Error::Meta("launch buy amount is 0".into()));
        }
        let sold = pool0
            .checked_sub(pool_in)
            .ok_or_else(|| Error::Meta("pool_in exceeds genesis pool".into()))?;
        match self.curve.as_str() {
            "lin" => {
                let base = parse_u128(self.base.as_deref().unwrap_or("0"), "base")?;
                let slope = parse_u128(self.slope.as_deref().unwrap_or("0"), "slope")?;
                linear_buy_cost(base, slope, sold, n)
            }
            "cpmm" => {
                let x0 = parse_u128(self.x.as_deref().unwrap_or("0"), "x")?;
                let y = pool_in;
                let x = cpmm_x(x0, pool0, y)?;
                cpmm_buy_cost(x, y, n)
            }
            _ => Err(Error::Meta("unknown curve".into())),
        }
    }

    /// Koinu to pay the seller who returns `n` units to the pool.
    pub fn sell_refund(&self, pool0: u128, pool_in: u128, n: u128) -> Result<u128, Error> {
        if n == 0 {
            return Err(Error::Meta("launch sell amount is 0".into()));
        }
        match self.curve.as_str() {
            "lin" => {
                let sold = pool0
                    .checked_sub(pool_in)
                    .ok_or_else(|| Error::Meta("pool_in exceeds genesis pool".into()))?;
                if n > sold {
                    return Err(Error::Meta(
                        "cannot sell more than the curve has sold".into(),
                    ));
                }
                let base = parse_u128(self.base.as_deref().unwrap_or("0"), "base")?;
                let slope = parse_u128(self.slope.as_deref().unwrap_or("0"), "slope")?;
                linear_buy_cost(base, slope, sold - n, n)
            }
            "cpmm" => {
                let x0 = parse_u128(self.x.as_deref().unwrap_or("0"), "x")?;
                let y = pool_in;
                let x = cpmm_x(x0, pool0, y)?;
                cpmm_sell_refund(x, y, n)
            }
            _ => Err(Error::Meta("unknown curve".into())),
        }
    }
}

fn parse_u128(s: &str, name: &str) -> Result<u128, Error> {
    s.parse::<u128>()
        .map_err(|_| Error::Meta(format!("launch.{name} is not a u128 decimal string")))
}

/// Σ_{i=0}^{n-1} (base + slope * (sold + i))
/// = n*base + slope * (n*sold + n*(n-1)/2)
pub fn linear_buy_cost(base: u128, slope: u128, sold: u128, n: u128) -> Result<u128, Error> {
    if n == 0 {
        return Err(Error::Meta("buy amount is 0".into()));
    }
    let n_base = n
        .checked_mul(base)
        .ok_or_else(|| Error::Meta("linear price overflow".into()))?;
    let n_sold = n
        .checked_mul(sold)
        .ok_or_else(|| Error::Meta("linear price overflow".into()))?;
    let n_minus = n.saturating_sub(1);
    let tri = n
        .checked_mul(n_minus)
        .ok_or_else(|| Error::Meta("linear price overflow".into()))?
        / 2;
    let inner = n_sold
        .checked_add(tri)
        .ok_or_else(|| Error::Meta("linear price overflow".into()))?;
    let slope_part = slope
        .checked_mul(inner)
        .ok_or_else(|| Error::Meta("linear price overflow".into()))?;
    n_base
        .checked_add(slope_part)
        .ok_or_else(|| Error::Meta("linear price overflow".into()))
}

/// Reconstruct CPMM doge reserve from k = x0 * pool0 and current token reserve y.
pub fn cpmm_x(x0: u128, pool0: u128, y: u128) -> Result<u128, Error> {
    if y == 0 {
        return Err(Error::Meta("cpmm token reserve is 0".into()));
    }
    let k = x0
        .checked_mul(pool0)
        .ok_or_else(|| Error::Meta("cpmm k overflow".into()))?;
    Ok(k / y)
}

/// cost = ceil(x * n / (y - n)). Must leave token reserve > 0.
pub fn cpmm_buy_cost(x: u128, y: u128, n: u128) -> Result<u128, Error> {
    if n == 0 || n >= y {
        return Err(Error::Meta("cpmm buy must leave token reserve > 0".into()));
    }
    let prod = x
        .checked_mul(n)
        .ok_or_else(|| Error::Meta("cpmm cost overflow".into()))?;
    let denom = y - n;
    Ok(prod / denom + u128::from(prod % denom != 0))
}

/// refund = floor(x * n / (y + n))
pub fn cpmm_sell_refund(x: u128, y: u128, n: u128) -> Result<u128, Error> {
    if n == 0 {
        return Err(Error::Meta("cpmm sell amount is 0".into()));
    }
    let prod = x
        .checked_mul(n)
        .ok_or_else(|| Error::Meta("cpmm refund overflow".into()))?;
    let denom = y
        .checked_add(n)
        .ok_or_else(|| Error::Meta("cpmm refund overflow".into()))?;
    Ok(prod / denom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_linear_constant() {
        assert_eq!(linear_buy_cost(2, 0, 0, 10).unwrap(), 20);
        assert_eq!(linear_buy_cost(1_000, 0, 50, 3).unwrap(), 3_000);
    }

    #[test]
    fn t_linear_slope_triangle() {
        // prices 0,1,2,3
        assert_eq!(linear_buy_cost(0, 1, 0, 4).unwrap(), 6);
        // reverse those four
        assert_eq!(linear_buy_cost(0, 1, 0, 4).unwrap(), 6);
    }

    #[test]
    fn t_cpmm_buy_ceil() {
        // ceil(1000*10/990) = ceil(10.101...) = 11
        assert_eq!(cpmm_buy_cost(1000, 1000, 10).unwrap(), 11);
    }

    #[test]
    fn t_cpmm_rejects_drain() {
        assert!(cpmm_buy_cost(1000, 1000, 1000).is_err());
    }

    #[test]
    fn t_spec_rejects_free_linear() {
        let pkh = [0xab; 20];
        assert!(LaunchSpec::linear(&pkh, 0, 0).is_err());
        assert!(LaunchSpec::linear(&pkh, 1, 0).is_ok());
    }
}
