//! Framework adapters for different web frameworks.

pub mod mock;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "actix-web")]
pub mod actix_web;

#[cfg(feature = "warp")]
pub mod warp;

// Note: The following adapters are work-in-progress and have compilation issues
// due to complex framework-specific API requirements. They are commented out
// to maintain compilation while work continues on their implementation.
// #[cfg(feature = "rocket")]
// pub mod rocket;
// #[cfg(feature = "salvo")]
// pub mod salvo;
// #[cfg(feature = "poem")]
// pub mod poem;
