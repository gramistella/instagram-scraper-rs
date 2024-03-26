//! # Errors
//!
//! This module exposes all the results and error types

use thiserror::Error;

pub type InstagramScraperResult<T> = Result<T, InstagramScraperError>;

/// Instagram scraper library error
#[derive(Debug, Error)]
pub enum InstagramScraperError {
    #[error("you are unauthenticated, you must call the login() method first")]
    Unauthenticated,
    #[error("csrf token is missing in the login response")]
    CsrfTokenIsMissing,
    #[error("authentication failed. Status: {status}, message: {message}")]
    AuthenticationFailed { status: String, message: String },
    #[error("HTTP request response has a bad status code: {0}")]
    RequestFailed(reqwest::StatusCode),
    #[error("response has a bad payload: {0}")]
    BadPayload(serde_json::Error),
    #[error("HTTP error: {0}")]
    Http(reqwest::Error),
    #[error("field not found: {0}")]
    FieldNotFound(String),
    #[error("Generic error: {0}")]
    Generic(String),
    #[error("Rate limited: {0}")]
    RateLimitExceeded(String),
    #[error("Parsing failed: {0}")]
    ParsingFailed(String),
    #[error("Upload failed: {0}")]
    UploadFailed(String),
}

impl From<serde_json::Error> for InstagramScraperError {
    fn from(e: serde_json::Error) -> Self {
        Self::BadPayload(e)
    }
}

impl From<reqwest::StatusCode> for InstagramScraperError {
    fn from(s: reqwest::StatusCode) -> Self {
        Self::RequestFailed(s)
    }
}

impl From<reqwest::Error> for InstagramScraperError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e)
    }
}
