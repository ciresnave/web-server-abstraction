//! # Web Server Abstraction - Production-Ready Framework
//!
//! A comprehensive, production-ready web server abstraction layer providing
//! a unified interface across multiple Rust web frameworks with enterprise-grade features.
//!
//! ## Key Features
//!
//! - **Framework Agnostic**: Unified API for Axum, Actix-Web, Warp, Rocket, Salvo, Poem
//! - **Ultra-Low Latency**: Optimized for sub-millisecond response times
//! - **Production Security**: CSRF, XSS protection, input sanitization, TLS/SSL
//! - **Unified Configuration**: Centralized configuration with multiple sources (file, env, remote)
//! - **Comprehensive Monitoring**: Metrics, distributed tracing, health checks, alerting
//! - **Multi-Language Support**: FFI layer for Python, Node.js, Go, and C integration
//! - **Performance Benchmarking**: Built-in latency and throughput validation
//! - **Enhanced Middleware**: CORS, compression, rate limiting, security headers
//! - **Type Safety**: Leverages Rust's type system for compile-time guarantees
//! - **Async First**: Built for modern async Rust with Tower ecosystem integration
//!
//! ## Supported Frameworks
//!
//! - **Axum** - High-performance async web framework
//! - **Actix-Web** - Actor-based web framework
//! - **Warp** - Composable web framework
//! - **Rocket** - Type-safe web framework
//! - **Salvo** - Simple and powerful web framework
//! - **Poem** - Fast and powerful web framework
//! - **Mock** - For testing and development
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use web_server_abstraction::{WebServer, HttpMethod, Response};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let server = WebServer::new()
//!         .route("/hello", HttpMethod::GET, |_req| async {
//!             Ok(Response::ok().body("Hello, Production World!"))
//!         })
//!         .route("/health", HttpMethod::GET, |_req| async {
//!             Ok(Response::ok()
//!                 .header("content-type", "application/json")
//!                 .body(r#"{"status": "healthy"}"#))
//!         })
//!         .bind("127.0.0.1:3000")
//!         .await?;
//!
//!     server.run().await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Production Configuration
//!
//! ```yaml
//! # config/server.yaml
//! server:
//!   host: "0.0.0.0"
//!   port: 8080
//!   workers: 4
//!
//! security:
//!   csrf_protection: true
//!   tls:
//!     enabled: true
//!     cert_path: "/path/to/cert.pem"
//!     key_path: "/path/to/key.pem"
//!
//! monitoring:
//!   metrics_enabled: true
//!   tracing_enabled: true
//!   health_checks_enabled: true
//! ```

pub mod adapters;
pub mod auth;
pub mod benchmarks;
pub mod config;
pub mod content;
pub mod core;
pub mod cross_platform_testing;
pub mod database;
pub mod enhanced_middleware;
pub mod error;
pub mod ffi;
pub mod middleware;
pub mod monitoring;
pub mod mountable;
pub mod performance;
pub mod routing;
pub mod security;
pub mod session;
pub mod state;
pub mod static_files;
pub mod types;

// Re-export core types and new production modules
pub use auth::{
    AuthContext, AuthContextConfig, AuthError, AuthMiddlewareResult, AuthRequirements,
    RequestAuthExt, UserSession, auth_middleware, enhanced_auth_middleware,
};
pub use config::{ConfigManager, MonitoringConfig, SecurityConfig, WebServerConfig};
pub use core::{Handler, HandlerFn, Route, WebServer};
pub use enhanced_middleware::{
    CompressionMiddleware, CorsMiddleware, EnhancedMiddleware, MiddlewareStack,
    RateLimitMiddleware, SecurityHeadersMiddleware,
};
pub use error::{Result, WebServerError};
pub use ffi::{FfiContext, ws_create_server as ffi_create_server};
pub use monitoring::{
    Alert, AlertSeverity, HealthStatus, MonitoringSystem, PerformanceStats, TraceContext,
};
pub use performance::{
    AdapterBenchmark, BenchmarkConfig, BenchmarkResults, LatencyCollector, PerformanceMetrics,
};
pub use security::SecurityStats;
pub use security::{
    CspMiddleware, CsrfMiddleware, SecurityContext, SecurityIssue, SecurityMiddleware,
    SecurityValidationResult, XssProtectionMiddleware, sanitize,
};
pub use types::{
    Cookie, FileUpload, Headers, HttpMethod, MultipartForm, Request, Response, StatusCode,
};

// Re-export existing modules
pub use content::{
    CompressionMiddleware as LegacyCompressionMiddleware, ContentNegotiationMiddleware,
};
pub use database::{
    ConnectionPool, DatabaseConfig, DatabaseConnection, DatabaseError, DatabaseValue,
    FromDatabaseValue, MockDatabase, PoolStats, QueryBuilder, Row, Transaction,
};
pub use mountable::{
    InterfaceBuilder, InterfaceRegistry, MountOptions, MountableInterface, OpenApiSpec,
    RouteDefinition, RouteDoc,
};
pub use routing::{Route as RoutePattern, Router};
pub use session::{MemorySessionStore, Session, SessionExt, SessionManager, SessionStore};
pub use state::{AppState, Config, Environment, SharedState};
pub use static_files::{
    StaticFileConfig, StaticFileHandler, serve_static, serve_static_with_prefix, static_files,
};

// Re-export benchmarking utilities (legacy)
pub use benchmarks::{
    BenchmarkConfig as LegacyBenchmarkConfig, BenchmarkResults as LegacyBenchmarkResults,
    PerformanceProfiler,
};

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
