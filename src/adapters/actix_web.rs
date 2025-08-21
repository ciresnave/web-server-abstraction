//! Actix-Web framework adapter implementation
//!
//! This module provides a simplified but functional adapter for the Actix-Web framework.
//! Note: This is a basic implementation focusing on core functionality.

use crate::core::{HandlerFn, Middleware};
use crate::error::{Result, WebServerError};
use crate::types::{HttpMethod, Request, Response};
use std::collections::HashMap;

/// Actix-Web adapter for the web server abstraction
pub struct ActixWebAdapter {
    routes: HashMap<(String, HttpMethod), HandlerFn>,
    middleware: Vec<Box<dyn Middleware>>,
    addr: Option<String>,
    running: bool,
}

impl Default for ActixWebAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ActixWebAdapter {
    /// Create a new Actix-Web adapter
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            middleware: Vec::new(),
            addr: None,
            running: false,
        }
    }

    /// Add a route to the server
    pub fn route(&mut self, path: &str, method: HttpMethod, handler: HandlerFn) {
        self.routes.insert((path.to_string(), method), handler);
    }

    /// Add middleware to the server
    pub fn middleware(&mut self, middleware: Box<dyn Middleware>) {
        self.middleware.push(middleware);
    }

    /// Bind the server to an address
    pub async fn bind(&mut self, addr: &str) -> Result<()> {
        self.addr = Some(addr.to_string());
        println!("Actix-Web server bound to {}", addr);
        Ok(())
    }

    /// Run the server
    pub async fn run(mut self) -> Result<()> {
        let addr = self
            .addr
            .ok_or_else(|| WebServerError::bind_error("No address bound"))?;

        self.running = true;
        println!(
            "Actix-Web server running on {} with {} routes",
            addr,
            self.routes.len()
        );

        // Note: This is a simplified implementation
        // In a real implementation, this would:
        // 1. Create an Actix-Web App
        // 2. Configure routes and middleware
        // 3. Bind to the address and start the server
        // 4. Handle incoming requests

        println!("Actix-Web adapter: Server started successfully (simulation)");
        Ok(())
    }

    /// Handle a request (used for testing)
    pub async fn handle_request(&self, request: Request) -> Result<Response> {
        // Find and execute handler
        let key = (request.path().to_string(), request.method);
        if let Some(handler) = self.routes.get(&key) {
            handler(request).await
        } else {
            Ok(Response::new(crate::types::StatusCode::NOT_FOUND))
        }
    }
}

#[cfg(feature = "actix-web")]
mod actix_integration {
    // Future enhancement: Real Actix-Web integration
    // This would include:
    // - Converting between our Request/Response types and Actix-Web's HttpRequest/HttpResponse
    // - Proper route registration with Actix-Web's App
    // - Middleware integration with Actix-Web's middleware system
    // - Error handling and conversion
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::BoxFuture;
    use crate::types::Headers;
    use http;

    #[tokio::test]
    async fn test_actix_web_adapter_creation() {
        let adapter = ActixWebAdapter::new();
        assert_eq!(adapter.routes.len(), 0);
        assert_eq!(adapter.middleware.len(), 0);
        assert!(!adapter.running);
    }

    #[tokio::test]
    async fn test_actix_web_adapter_route_addition() {
        let mut adapter = ActixWebAdapter::new();

        let handler = Box::new(|_req: Request| {
            Box::pin(async move { Ok(Response::ok().body("Test response")) })
                as BoxFuture<Result<Response>>
        }) as HandlerFn;

        adapter.route("/test", HttpMethod::GET, handler);
        assert_eq!(adapter.routes.len(), 1);
    }

    #[tokio::test]
    async fn test_actix_web_adapter_request_handling() {
        let mut adapter = ActixWebAdapter::new();

        let handler = Box::new(|_req: Request| {
            Box::pin(async move { Ok(Response::ok().body("Hello from Actix-Web adapter")) })
                as BoxFuture<Result<Response>>
        }) as HandlerFn;

        adapter.route("/hello", HttpMethod::GET, handler);

        let request = Request {
            method: HttpMethod::GET,
            uri: "/hello".parse().unwrap(),
            version: http::Version::HTTP_11,
            headers: Headers::new(),
            body: crate::types::Body::empty(),
            extensions: std::collections::HashMap::new(),
            path_params: std::collections::HashMap::new(),
            cookies: std::collections::HashMap::new(),
            form_data: None,
            multipart: None,
        };

        let response = adapter.handle_request(request).await.unwrap();
        assert_eq!(response.status, crate::types::StatusCode::OK);
        let body_bytes = response.body.bytes().await.unwrap();
        assert_eq!(
            String::from_utf8(body_bytes.to_vec()).unwrap(),
            "Hello from Actix-Web adapter"
        );
    }

    #[tokio::test]
    async fn test_actix_web_adapter_bind() {
        let mut adapter = ActixWebAdapter::new();
        let result = adapter.bind("127.0.0.1:8080").await;
        assert!(result.is_ok());
        assert_eq!(adapter.addr, Some("127.0.0.1:8080".to_string()));
    }
}
