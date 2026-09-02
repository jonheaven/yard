use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("address: {0}")]
    Address(String),
    #[error("wif: {0}")]
    Wif(String),
    #[error("amount: {0}")]
    Amount(String),
    #[error("tx: {0}")]
    Tx(String),
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("http: {0}")]
    Http(String),
    #[error(transparent)]
    Core(#[from] yard_core::Error),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e.to_string())
    }
}
