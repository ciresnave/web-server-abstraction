//! Framework adapters for different web frameworks.

pub mod mock;

#[cfg(feature = "axum")]
pub mod axum;

// Framework adapters currently being updated for new framework versions
// These will be re-enabled in future releases once updated for latest APIs
// #[cfg(feature = "actix-web")]
// pub mod actix_web;

// #[cfg(feature = "warp")]
// pub mod warp;

// #[cfg(feature = "rocket")]
// pub mod rocket;

// #[cfg(feature = "salvo")]
// pub mod salvo;

// #[cfg(feature = "poem")]
// pub mod poem;
