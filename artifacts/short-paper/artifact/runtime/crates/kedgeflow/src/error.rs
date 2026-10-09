#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("authority refused: {0}")]
    Refused(String),
    #[error("nonce consumed")]
    NonceConsumed,
    #[error("dependency unavailable: {0}")]
    Unavailable(String),
    #[error("effect outcome unknown: {0}")]
    Unknown(String),
}
pub type Result<T> = std::result::Result<T, Error>;

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Invalid(error.to_string())
    }
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Unavailable(error.to_string())
    }
}
impl From<reqwest::Error> for Error {
    fn from(_: reqwest::Error) -> Self {
        // URLs/credentials/response bodies must not leak through transport errors.
        Self::Unavailable("HTTP transport failed".into())
    }
}
