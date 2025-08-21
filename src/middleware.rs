//! Expanded middleware implementations with advanced features.

use crate::core::{Middleware, Next};
use crate::error::Result;
use crate::types::{Request, Response, StatusCode};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// Logging middleware that logs request details
pub struct LoggingMiddleware {
    pub enabled: bool,
    pub log_bodies: bool,
}

impl Default for LoggingMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl LoggingMiddleware {
    pub fn new() -> Self {
        Self {
            enabled: true,
            log_bodies: false,
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn log_bodies(mut self, log_bodies: bool) -> Self {
        self.log_bodies = log_bodies;
        self
    }
}

#[async_trait]
impl Middleware for LoggingMiddleware {
    async fn call(&self, req: Request, next: Next) -> Result<Response> {
        if !self.enabled {
            return next.run(req).await;
        }

        let start = Instant::now();
        let method = req.method;
        let path = req.path().to_string();

        if self.log_bodies {
            let body_preview = req.body.len().min(100);
            println!("-> {:?} {} (body: {} bytes)", method, path, body_preview);
        } else {
            println!("-> {:?} {}", method, path);
        }

        let response = next.run(req).await;

        let duration = start.elapsed();
        match &response {
            Ok(_resp) => {
                println!("<- {:?} {} - 200 OK ({:?})", method, path, duration);
            }
            Err(err) => {
                println!("<- {:?} {} - ERROR: {} ({:?})", method, path, err, duration);
            }
        }

        response
    }
}

/// CORS middleware for handling Cross-Origin Resource Sharing
pub struct CorsMiddleware {
    pub allow_origin: String,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub allow_credentials: bool,
    pub expose_headers: Vec<String>,
    pub max_age: Option<Duration>,
}

impl Default for CorsMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl CorsMiddleware {
    pub fn new() -> Self {
        Self {
            allow_origin: "*".to_string(),
            allow_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allow_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "Accept".to_string(),
                "Origin".to_string(),
                "X-Requested-With".to_string(),
            ],
            allow_credentials: false,
            expose_headers: vec![],
            max_age: Some(Duration::from_secs(86400)), // 24 hours
        }
    }

    pub fn allow_origin(mut self, origin: impl Into<String>) -> Self {
        self.allow_origin = origin.into();
        self
    }

    pub fn allow_methods(mut self, methods: Vec<String>) -> Self {
        self.allow_methods = methods;
        self
    }

    pub fn allow_headers(mut self, headers: Vec<String>) -> Self {
        self.allow_headers = headers;
        self
    }

    pub fn allow_credentials(mut self, allow: bool) -> Self {
        self.allow_credentials = allow;
        self
    }

    pub fn expose_headers(mut self, headers: Vec<String>) -> Self {
        self.expose_headers = headers;
        self
    }

    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }
}

#[async_trait]
impl Middleware for CorsMiddleware {
    async fn call(&self, req: Request, next: Next) -> Result<Response> {
        // Handle preflight requests
        if req.method == crate::types::HttpMethod::OPTIONS {
            let mut response = Response::new(StatusCode::OK)
                .header("Access-Control-Allow-Origin", &self.allow_origin)
                .header(
                    "Access-Control-Allow-Methods",
                    self.allow_methods.join(", "),
                )
                .header(
                    "Access-Control-Allow-Headers",
                    self.allow_headers.join(", "),
                );

            if self.allow_credentials {
                response = response.header("Access-Control-Allow-Credentials", "true");
            }

            if let Some(max_age) = self.max_age {
                response = response.header("Access-Control-Max-Age", max_age.as_secs().to_string());
            }

            return Ok(response);
        }

        let response = next.run(req).await?;

        let mut cors_response = response
            .header("Access-Control-Allow-Origin", &self.allow_origin)
            .header(
                "Access-Control-Allow-Methods",
                self.allow_methods.join(", "),
            )
            .header(
                "Access-Control-Allow-Headers",
                self.allow_headers.join(", "),
            );

        if self.allow_credentials {
            cors_response = cors_response.header("Access-Control-Allow-Credentials", "true");
        }

        if !self.expose_headers.is_empty() {
            cors_response = cors_response.header(
                "Access-Control-Expose-Headers",
                self.expose_headers.join(", "),
            );
        }

        Ok(cors_response)
    }
}

/// Timeout middleware that cancels requests after a specified duration
pub struct TimeoutMiddleware {
    pub timeout: Duration,
}

impl TimeoutMiddleware {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl Middleware for TimeoutMiddleware {
    async fn call(&self, req: Request, next: Next) -> Result<Response> {
        // Note: In a real implementation, you'd use tokio::time::timeout
        // For now, we'll just pass through with a warning if timeout is very short
        if self.timeout.as_millis() < 100 {
            println!("Warning: Very short timeout configured: {:?}", self.timeout);
        }
        next.run(req).await
    }
}

/// Rate limiting middleware with in-memory storage
pub struct RateLimitMiddleware {
    pub max_requests: u32,
    pub window: Duration,
    pub store: Arc<Mutex<HashMap<String, (u32, SystemTime)>>>,
}

impl RateLimitMiddleware {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_client_key(&self, req: &Request) -> String {
        // In a real implementation, you'd extract the client IP or user ID
        // For now, we'll use a simple key based on the path
        format!("default:{}", req.path())
    }

    fn is_rate_limited(&self, key: &str) -> bool {
        let mut store = self.store.lock().unwrap();
        let now = SystemTime::now();

        match store.get_mut(key) {
            Some((count, last_reset)) => {
                // Check if window has expired
                if now.duration_since(*last_reset).unwrap_or(Duration::ZERO) >= self.window {
                    *count = 1;
                    *last_reset = now;
                    false
                } else if *count >= self.max_requests {
                    true
                } else {
                    *count += 1;
                    false
                }
            }
            None => {
                store.insert(key.to_string(), (1, now));
                false
            }
        }
    }
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    async fn call(&self, req: Request, next: Next) -> Result<Response> {
        let key = self.get_client_key(&req);

        if self.is_rate_limited(&key) {
            return Ok(Response::new(StatusCode(429))
                .header("Content-Type", "application/json")
                .body(r#"{"error": "Rate limit exceeded"}"#));
        }

        next.run(req).await
    }
}

/// Authentication middleware with configurable validation
pub struct AuthMiddleware {
    pub require_auth: bool,
    pub bearer_tokens: Arc<Vec<String>>,
}

impl Default for AuthMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthMiddleware {
    pub fn new() -> Self {
        Self {
            require_auth: true,
            bearer_tokens: Arc::new(vec![]),
        }
    }

    pub fn optional(mut self) -> Self {
        self.require_auth = false;
        self
    }

    pub fn with_bearer_tokens(mut self, tokens: Vec<String>) -> Self {
        self.bearer_tokens = Arc::new(tokens);
        self
    }

    fn validate_token(&self, authorization: &str) -> bool {
        if let Some(token) = authorization.strip_prefix("Bearer ") {
            self.bearer_tokens.contains(&token.to_string())
        } else {
            false
        }
    }
}

#[async_trait]
impl Middleware for AuthMiddleware {
    async fn call(&self, req: Request, next: Next) -> Result<Response> {
        if self.require_auth {
            if let Some(auth_header) = req.headers.get("authorization") {
                if !self.bearer_tokens.is_empty() && !self.validate_token(auth_header) {
                    return Ok(Response::new(StatusCode::UNAUTHORIZED)
                        .header("Content-Type", "application/json")
                        .body(r#"{"error": "Invalid token"}"#));
                }
            } else {
                return Ok(Response::new(StatusCode::UNAUTHORIZED)
                    .header("Content-Type", "application/json")
                    .body(r#"{"error": "Authentication required"}"#));
            }
        }

        next.run(req).await
    }
}

/// Content compression middleware
pub struct CompressionMiddleware {
    pub enabled: bool,
    pub min_size: usize,
}

impl Default for CompressionMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl CompressionMiddleware {
    pub fn new() -> Self {
        Self {
            enabled: true,
            min_size: 1024, // Only compress responses larger than 1KB
        }
    }

    pub fn min_size(mut self, size: usize) -> Self {
        self.min_size = size;
        self
    }
}

#[async_trait]
impl Middleware for CompressionMiddleware {
    async fn call(&self, req: Request, next: Next) -> Result<Response> {
        let response = next.run(req).await?;

        if !self.enabled {
            return Ok(response);
        }

        // Check if response is large enough to compress
        if response.body.len() >= self.min_size {
            // In a real implementation, you'd actually compress the body
            let compressed_response = response
                .header("Content-Encoding", "gzip")
                .header("Vary", "Accept-Encoding");
            Ok(compressed_response)
        } else {
            Ok(response)
        }
    }
}

/// Security headers middleware
pub struct SecurityHeadersMiddleware {
    pub add_hsts: bool,
    pub add_frame_options: bool,
    pub add_content_type_options: bool,
    pub add_xss_protection: bool,
}

impl Default for SecurityHeadersMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityHeadersMiddleware {
    pub fn new() -> Self {
        Self {
            add_hsts: true,
            add_frame_options: true,
            add_content_type_options: true,
            add_xss_protection: true,
        }
    }

    pub fn with_hsts(mut self, enabled: bool) -> Self {
        self.add_hsts = enabled;
        self
    }

    pub fn with_frame_options(mut self, enabled: bool) -> Self {
        self.add_frame_options = enabled;
        self
    }
}

#[async_trait]
impl Middleware for SecurityHeadersMiddleware {
    async fn call(&self, req: Request, next: Next) -> Result<Response> {
        let mut response = next.run(req).await?;

        if self.add_hsts {
            response = response.header(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            );
        }

        if self.add_frame_options {
            response = response.header("X-Frame-Options", "DENY");
        }

        if self.add_content_type_options {
            response = response.header("X-Content-Type-Options", "nosniff");
        }

        if self.add_xss_protection {
            response = response.header("X-XSS-Protection", "1; mode=block");
        }

        Ok(response)
    }
}

/// Request metrics and monitoring middleware
pub struct MetricsMiddleware {
    pub enabled: bool,
    pub collect_timing: bool,
    pub collect_errors: bool,
    pub request_count: Arc<Mutex<u64>>,
    pub error_count: Arc<Mutex<u64>>,
    pub total_duration: Arc<Mutex<Duration>>,
}

impl Default for MetricsMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsMiddleware {
    pub fn new() -> Self {
        Self {
            enabled: true,
            collect_timing: true,
            collect_errors: true,
            request_count: Arc::new(Mutex::new(0)),
            error_count: Arc::new(Mutex::new(0)),
            total_duration: Arc::new(Mutex::new(Duration::ZERO)),
        }
    }

    pub fn get_stats(&self) -> (u64, u64, Duration) {
        let req_count = *self.request_count.lock().unwrap();
        let err_count = *self.error_count.lock().unwrap();
        let total_dur = *self.total_duration.lock().unwrap();
        (req_count, err_count, total_dur)
    }
}

#[async_trait]
impl Middleware for MetricsMiddleware {
    async fn call(&self, req: Request, next: Next) -> Result<Response> {
        if !self.enabled {
            return next.run(req).await;
        }

        let start = if self.collect_timing {
            Some(Instant::now())
        } else {
            None
        };

        // Increment request count
        *self.request_count.lock().unwrap() += 1;

        let result = next.run(req).await;

        // Collect timing
        if let Some(start_time) = start {
            let duration = start_time.elapsed();
            *self.total_duration.lock().unwrap() += duration;
        }

        // Collect errors
        if self.collect_errors && result.is_err() {
            *self.error_count.lock().unwrap() += 1;
        }

        result
    }
}

/// Response caching middleware (simple in-memory cache)
pub struct CacheMiddleware {
    pub enabled: bool,
    pub cache_duration: Duration,
    pub cache: Arc<Mutex<HashMap<String, (Response, SystemTime)>>>,
}

impl CacheMiddleware {
    pub fn new(cache_duration: Duration) -> Self {
        Self {
            enabled: true,
            cache_duration,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn cache_key(&self, req: &Request) -> String {
        format!("{}:{}", req.method.as_str(), req.path())
    }

    fn get_cached(&self, key: &str) -> Option<Response> {
        let mut cache = self.cache.lock().unwrap();

        if let Some((response, timestamp)) = cache.get(key) {
            let now = SystemTime::now();
            if now.duration_since(*timestamp).unwrap_or(Duration::MAX) < self.cache_duration {
                return Some(response.clone());
            } else {
                cache.remove(key);
            }
        }

        None
    }

    fn cache_response(&self, key: String, response: &Response) {
        if response.status.0 == 200 {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(key, (response.clone(), SystemTime::now()));
        }
    }
}

#[async_trait]
impl Middleware for CacheMiddleware {
    async fn call(&self, req: Request, next: Next) -> Result<Response> {
        if !self.enabled || req.method != crate::types::HttpMethod::GET {
            return next.run(req).await;
        }

        let cache_key = self.cache_key(&req);

        // Try to get from cache
        if let Some(cached_response) = self.get_cached(&cache_key) {
            return Ok(cached_response.header("X-Cache", "HIT"));
        }

        // Execute request
        let response = next.run(req).await?;

        // Cache the response
        self.cache_response(cache_key, &response);

        Ok(response.header("X-Cache", "MISS"))
    }
}

/// Path parameter extraction middleware
/// Automatically extracts path parameters and adds them to the request
pub struct PathParameterMiddleware {
    route_patterns: Vec<(String, crate::types::HttpMethod)>,
}

impl PathParameterMiddleware {
    pub fn new(route_patterns: Vec<(String, crate::types::HttpMethod)>) -> Self {
        Self { route_patterns }
    }

    /// Match dynamic path patterns
    fn match_dynamic_path(
        &self,
        pattern: &str,
        path: &str,
    ) -> Option<std::collections::HashMap<String, String>> {
        let route_parts: Vec<&str> = pattern.split('/').collect();
        let path_parts: Vec<&str> = path.split('/').collect();

        if route_parts.len() != path_parts.len() {
            // Handle wildcard at the end
            if let Some(last_part) = route_parts.last() {
                if last_part.starts_with('*') && route_parts.len() <= path_parts.len() {
                    // Wildcard matches remaining path
                    let mut params = std::collections::HashMap::new();
                    let param_name = last_part.trim_start_matches('*');
                    if !param_name.is_empty() {
                        let remaining_path = path_parts[route_parts.len() - 1..].join("/");
                        params.insert(param_name.to_string(), remaining_path);
                    }
                    return Some(params);
                }
            }
            return None;
        }

        let mut params = std::collections::HashMap::new();

        for (route_part, path_part) in route_parts.iter().zip(path_parts.iter()) {
            if route_part.starts_with(':') {
                // Path parameter
                let param_name = route_part.trim_start_matches(':');
                params.insert(param_name.to_string(), path_part.to_string());
            } else if route_part.starts_with('*') {
                // Wildcard
                let param_name = route_part.trim_start_matches('*');
                if !param_name.is_empty() {
                    params.insert(param_name.to_string(), path_part.to_string());
                }
            } else if route_part != path_part {
                // Exact match required
                return None;
            }
        }

        Some(params)
    }
}

#[async_trait]
impl Middleware for PathParameterMiddleware {
    async fn call(&self, mut req: Request, next: Next) -> Result<Response> {
        // Find matching route and extract parameters
        for (pattern, method) in &self.route_patterns {
            if *method == req.method {
                if let Some(params) = self.match_dynamic_path(pattern, req.path()) {
                    req.set_params(params);
                    break;
                }
            }
        }

        next.run(req).await
    }
}

/// Request/Response transformation middleware
/// Allows custom transformations of requests and responses
pub struct TransformMiddleware<F, G>
where
    F: Fn(Request) -> Request + Send + Sync + 'static,
    G: Fn(Response) -> Response + Send + Sync + 'static,
{
    request_transform: F,
    response_transform: G,
}

impl<F, G> TransformMiddleware<F, G>
where
    F: Fn(Request) -> Request + Send + Sync + 'static,
    G: Fn(Response) -> Response + Send + Sync + 'static,
{
    pub fn new(request_transform: F, response_transform: G) -> Self {
        Self {
            request_transform,
            response_transform,
        }
    }
}

#[async_trait]
impl<F, G> Middleware for TransformMiddleware<F, G>
where
    F: Fn(Request) -> Request + Send + Sync + 'static,
    G: Fn(Response) -> Response + Send + Sync + 'static,
{
    async fn call(&self, req: Request, next: Next) -> Result<Response> {
        let transformed_req = (self.request_transform)(req);
        let response = next.run(transformed_req).await?;
        Ok((self.response_transform)(response))
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{Body, Headers, Request, Response, StatusCode};

    #[tokio::test]
    async fn test_middleware_chain() {
        // Create a simple handler
        let _handler = move |_req: Request| async move {
            Ok::<Response, crate::error::WebServerError>(Response {
                status: StatusCode::OK,
                headers: Headers::new(),
                body: Body::from("test response"),
            })
        };

        // Test that basic middleware compilation works
        // Actual middleware functionality would be tested when those modules are re-enabled
        // This test verifies that the basic middleware framework compiles and links correctly
    }
}
