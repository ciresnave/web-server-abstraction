//! Framework adapters for different web frameworks.

pub mod mock;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "actix-web")]
pub mod actix_web;

#[cfg(feature = "warp")]
pub mod warp;

#[cfg(feature = "rocket")]
pub mod rocket;

#[cfg(feature = "salvo")]
pub mod salvo;

#[cfg(feature = "poem")]
pub mod poem;
