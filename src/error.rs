//! Error types for the web server abstraction.

use thiserror::Error;

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, WebServerError>;

/// Main error type for the web server abstraction
#[derive(Error, Debug)]
pub enum WebServerError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] http::Error),

    #[error("Bind error: {0}")]
    BindError(String),

    #[error("Route error: {0}")]
    RouteError(String),

    #[error("Middleware error: {0}")]
    MiddlewareError(String),

    #[error("Framework adapter error: {0}")]
    AdapterError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Authentication error: {0}")]
    AuthError(String),

    #[error("Custom error: {0}")]
    Custom(String),
}

impl WebServerError {
    /// Create a custom error
    pub fn custom(msg: impl Into<String>) -> Self {
        Self::Custom(msg.into())
    }

    /// Create a bind error
    pub fn bind_error(msg: impl Into<String>) -> Self {
        Self::BindError(msg.into())
    }

    /// Create a route error
    pub fn route_error(msg: impl Into<String>) -> Self {
        Self::RouteError(msg.into())
    }

    /// Create a middleware error
    pub fn middleware_error(msg: impl Into<String>) -> Self {
        Self::MiddlewareError(msg.into())
    }

    /// Create an adapter error
    pub fn adapter_error(msg: impl Into<String>) -> Self {
        Self::AdapterError(msg.into())
    }

    /// Create a parse error
    pub fn parse_error(msg: impl Into<String>) -> Self {
        Self::Custom(format!("Parse error: {}", msg.into()))
    }
}
