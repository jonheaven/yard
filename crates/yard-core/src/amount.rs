use crate::Error;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Consensus amount: integer base units. Display decimals live in genesis meta only.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Amount(pub u128);

impl Amount {
    pub const ZERO: Self = Self(0);

    pub fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    pub fn from_le_bytes(b: [u8; 16]) -> Self {
        Self(u128::from_le_bytes(b))
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Amount {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u128>()
            .map(Amount)
            .map_err(|_| Error::Decode(format!("invalid amount {s:?}")))
    }
}

impl From<u128> for Amount {
    fn from(v: u128) -> Self {
        Self(v)
    }
}
