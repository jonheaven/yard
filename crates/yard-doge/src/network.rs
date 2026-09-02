use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    pub fn p2pkh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x1e,
            Network::Testnet | Network::Regtest => 0x71,
        }
    }

    pub fn p2sh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x16,
            Network::Testnet | Network::Regtest => 0xc4,
        }
    }

    pub fn wif_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x9e,
            Network::Testnet | Network::Regtest => 0xf1,
        }
    }

    pub fn default_rpc_port(self) -> u16 {
        match self {
            Network::Mainnet => 22555,
            Network::Testnet => 44555,
            Network::Regtest => 18332,
        }
    }

    pub fn default_rpc_url(self) -> String {
        format!("http://yard:yard@127.0.0.1:{}", self.default_rpc_port())
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "main" | "mainnet" => Ok(Network::Mainnet),
            "test" | "testnet" => Ok(Network::Testnet),
            "regtest" => Ok(Network::Regtest),
            other => Err(format!("unknown network {other}")),
        }
    }
}
