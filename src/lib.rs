//! # Web Serve/// ## Supported Frameworks
//!
//! - Mock (for testing)
//! - Axum
//! - Actix-Web
//! - Warpction
//!
//! An ergonomic abstraction layer over popular Rust web frameworks.
//!
//! This crate provides a unified interface for building web applications that can
//! run on multiple web frameworks without changing your application code.
//!
//! ## Features
//!
//! - **Framework Agnostic**: Write once, run on any supported framework
//! - **Type Safe**: Leverages Rust's type system for compile-time guarantees
//! - **Async First**: Built for modern async Rust
//! - **Middleware Support**: Composable middleware system
//! - **Tower Integration**: Built on the Tower ecosystem
//!
//! ## Supported Frameworks
//!
//! - Axum
//! - Actix-Web
//! - Rocket
//! - Warp
//! - Salvo
//! - Poem
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use web_server_abstraction::{WebServer, Route, HttpMethod, Response};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let server = WebServer::new()
//!         .route("/hello", HttpMethod::GET, |_req| async {
//!             Ok(Response::ok().body("Hello, World!"))
//!         })
//!         .bind("127.0.0.1:3000")
//!         .await?;
//!
//!     server.run().await?;
//!     Ok(())
//! }
//! ```

pub mod adapters;
pub mod auth;
pub mod benchmarks;
pub mod content;
pub mod core;
pub mod database;
pub mod error;
pub mod middleware;
pub mod mountable;
pub mod routing;
pub mod security;
pub mod session;
pub mod state;
pub mod static_files;
pub mod types;

// Re-export core types
pub use auth::{
    auth_middleware, enhanced_auth_middleware, AuthContext, AuthContextConfig, AuthError,
    AuthMiddlewareResult, AuthRequirements, RequestAuthExt, UserSession,
};
pub use core::{Handler, HandlerFn, Route, WebServer};
pub use error::{Result, WebServerError};
pub use types::{
    Cookie, FileUpload, Headers, HttpMethod, MultipartForm, Request, Response, StatusCode,
};

// Re-export new modules
pub use content::{CompressionMiddleware, ContentNegotiationMiddleware};
pub use database::{
    ConnectionPool, DatabaseConfig, DatabaseConnection, DatabaseError, DatabaseValue,
    FromDatabaseValue, MockDatabase, PoolStats, QueryBuilder, Row, Transaction,
};
pub use mountable::{
    InterfaceBuilder, InterfaceRegistry, MountOptions, MountableInterface, OpenApiSpec,
    RouteDefinition, RouteDoc,
};
pub use routing::{Route as RoutePattern, Router};
pub use security::{sanitize, CspMiddleware, CsrfMiddleware, XssProtectionMiddleware};
pub use session::{MemorySessionStore, Session, SessionExt, SessionManager, SessionStore};
pub use state::{AppState, Config, Environment, SharedState};
pub use static_files::{
    serve_static, serve_static_with_prefix, static_files, StaticFileConfig, StaticFileHandler,
};

// Re-export benchmarking utilities
pub use benchmarks::{BenchmarkConfig, BenchmarkResults, PerformanceProfiler};

// Re-export framework adapters when features are enabled
pub use adapters::mock::MockAdapter;

#[cfg(feature = "axum")]
pub use adapters::axum::AxumAdapter;

#[cfg(feature = "actix-web")]
pub use adapters::actix_web::ActixWebAdapter;

#[cfg(feature = "warp")]
pub use adapters::warp::WarpAdapter;

#[cfg(feature = "rocket")]
pub use adapters::rocket::RocketAdapter;

#[cfg(feature = "salvo")]
pub use adapters::salvo::SalvoAdapter;

#[cfg(feature = "poem")]
pub use adapters::poem::PoemAdapter;
