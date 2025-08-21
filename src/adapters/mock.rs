//! Mock adapter for testing and demonstration purposes.

use crate::core::{HandlerFn, Middleware};
use crate::error::{Result, WebServerError};
use crate::types::{HttpMethod, Request, Response, StatusCode};
use std::collections::HashMap;

/// Mock web server adapter for testing
pub struct MockAdapter {
    routes: HashMap<(String, HttpMethod), HandlerFn>,
    middleware: Vec<Box<dyn Middleware>>,
    addr: Option<String>,
    running: bool,
}

impl Default for MockAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl MockAdapter {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            middleware: Vec::new(),
            addr: None,
            running: false,
        }
    }

    /// Bind the server to an address
    pub async fn bind(&mut self, addr: &str) -> Result<()> {
        self.addr = Some(addr.to_string());
        println!("Mock server bound to {}", addr);
        Ok(())
    }

    /// Run the server
    pub async fn run(mut self) -> Result<()> {
        let addr = self
            .addr
            .ok_or_else(|| WebServerError::bind_error("No address bound"))?;

        self.running = true;
        println!(
            "Mock server running on {} with {} routes",
            addr,
            self.routes.len()
        );

        // In a real server, this would be an infinite loop handling requests
        // For the mock, we'll just simulate that it's running
        println!("Mock server would run indefinitely here...");

        Ok(())
    }

    /// Add a route to the server
    pub fn route(&mut self, path: &str, method: HttpMethod, handler: HandlerFn) -> &mut Self {
        let route_key = (path.to_string(), method);
        self.routes.insert(route_key, handler);
        println!("Added route: {:?} {}", method, path);
        self
    }

    /// Add middleware to the server
    pub fn middleware(&mut self, middleware: Box<dyn Middleware>) -> &mut Self {
        self.middleware.push(middleware);
        println!("Added middleware");
        self
    }

    /// Simulate a request for testing
    pub async fn simulate_request(&self, method: HttpMethod, path: &str) -> Result<Response> {
        let route_key = (path.to_string(), method);

        if let Some(handler) = self.routes.get(&route_key) {
            let request = Request::new(method, path.parse().unwrap());
            handler(request).await
        } else {
            Ok(Response::new(StatusCode::NOT_FOUND).body("Route not found"))
        }
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn get_bound_address(&self) -> Option<&String> {
        self.addr.as_ref()
    }
}
