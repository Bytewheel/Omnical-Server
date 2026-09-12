use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchedulingError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SMTP error: {0}")]
    Smtp(String),

    #[error("SMTP connection closed unexpectedly")]
    SmtpUnexpectedEof,

    #[error("IMAP error: {0}")]
    Imap(String),

    #[error("Store error: {0}")]
    Store(#[from] rustical_store::Error),
}
