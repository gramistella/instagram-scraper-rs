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
    #[error("Upload failed (recoverable): {0}")]
    UploadFailedRecoverable(String),
    #[error("Upload failed (non recoverable): {0}")]
    UploadFailedNonRecoverable(String),
    #[error("Upload succeeded but failed to retrieve media id after upload: {0}")]
    UploadSucceededButFailedToRetrieveId(String),
    #[error("Account suspended")]
    AccountSuspended,
    #[error("Challenge required")]
    ChallengeRequired,
    #[error("User {0} not found. Maybe it's private or doesn't exist.")]
    UserNotFound(String),
    #[error("Media {0} not found. Maybe it's private or doesn't exist.")]
    MediaNotFound(String),
    #[error("Failed to comment: {0}")]
    CommentFailed(String),
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

#[derive(Serialize, Deserialize)]
pub struct SharedDataInnerError {
    pub user: serde_json::Value,
}
#[derive(Serialize, Deserialize)]
pub struct SharedDataInnerErrorResponse {
    pub data: SharedDataInnerError,
    pub status: String,
}

#[derive(Serialize, Deserialize)]
pub struct ReelNotFoundInnerData {
    pub shortcode_media: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct ReelNotFoundInnerExtensions {
    pub is_final: serde_json::Value,
}
#[derive(Serialize, Deserialize)]
pub struct ReelNotFoundStruct {
    pub data: ReelNotFoundInnerData,
    pub extensions: ReelNotFoundInnerExtensions,
    pub status: String,
}


pub type InstagramUploaderResult<T> = Result<T, InstagramUploaderError>;

/// Instagram scraper library error
#[derive(Debug, Error)]
pub enum InstagramUploaderError {
    #[error("Upload failed (recoverable): {0}")]
    UploadFailedRecoverable(String),
    #[error("Upload failed (non recoverable): {0}")]
    UploadFailedNonRecoverable(String),
    #[error("Upload succeeded but failed to retrieve media id after upload: {0}")]
    UploadSucceededButFailedToRetrieveId(String),
}

pub type InstagramCommentResult<T> = Result<T, InstagramCommentError>;

/// Instagram scraper library error
#[derive(Debug, Error)]
pub enum InstagramCommentError {
    #[error("Failed to comment: {0}")]
    CommentFailed(String),
}