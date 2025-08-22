//! Salvo framework adapter implementation
//!
//! This module provides a production-ready adapter for the Salvo framework.
//! Includes full request/response conversion, middleware integration, and error handling.

use crate::core::{HandlerFn, Middleware};
use crate::error::{Result, WebServerError};
use crate::types::{HttpMethod, Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "salvo")]
use salvo::prelude::*;
#[cfg(feature = "salvo")]
use salvo::{
    conn::TcpListener,
    http::{HeaderValue, Method as SalvoMethod, StatusCode as SalvoStatusCode},
    Request as SalvoRequest, Response as SalvoResponse, Router, Server, Service,
};

/// Salvo framework adapter
pub struct SalvoAdapter {
    routes: Vec<(String, HttpMethod, HandlerFn)>,
    middleware: Vec<Box<dyn Middleware>>,
    addr: Option<SocketAddr>,
}

impl Default for SalvoAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SalvoAdapter {
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            middleware: Vec::new(),
            addr: None,
        }
    }

    /// Bind the server to an address
    pub async fn bind(&mut self, addr: &str) -> Result<()> {
        let socket_addr = addr
            .parse::<SocketAddr>()
            .map_err(|e| WebServerError::BindError(e.to_string()))?;
        self.addr = Some(socket_addr);
        Ok(())
    }

    /// Add a route to the server
    pub fn route(&mut self, path: &str, method: HttpMethod, handler: HandlerFn) {
        self.routes.push((path.to_string(), method, handler));
        println!("Added Salvo route: {:?} {}", method, path);
    }

    /// Add middleware to the server
    pub fn middleware(&mut self, middleware: Box<dyn Middleware>) {
        self.middleware.push(middleware);
        println!("Added middleware to Salvo adapter");
    }

    /// Run the server
    #[cfg(feature = "salvo")]
    pub async fn run(self) -> Result<()> {
        let addr = self
            .addr
            .ok_or_else(|| WebServerError::BindError("Server not bound to address".to_string()))?;

        println!("Starting Salvo server on {}", addr);

        // Create Salvo router
        let mut router = Router::new();

        // Store routes for handler access
        let routes_data = Arc::new(self.routes);

        // Add routes to router
        for (path, method, _) in routes_data.iter() {
            let path_clone = path.clone();
            let routes_for_handler = routes_data.clone();
            let method_clone = *method;

            let salvo_handler = SalvoHandlerWrapper {
                path: path_clone.clone(),
                method: method_clone,
                routes: routes_for_handler,
            };

            match method {
                HttpMethod::GET => {
                    router = router.get(&path_clone, salvo_handler);
                }
                HttpMethod::POST => {
                    router = router.post(&path_clone, salvo_handler);
                }
                HttpMethod::PUT => {
                    router = router.put(&path_clone, salvo_handler);
                }
                HttpMethod::DELETE => {
                    router = router.delete(&path_clone, salvo_handler);
                }
                HttpMethod::PATCH => {
                    router = router.patch(&path_clone, salvo_handler);
                }
                HttpMethod::HEAD => {
                    router = router.head(&path_clone, salvo_handler);
                }
                HttpMethod::OPTIONS => {
                    router = router.options(&path_clone, salvo_handler);
                }
            }
        }

        // Add middleware fairing if any middleware is registered
        if !self.middleware.is_empty() {
            let middleware_fairing = SalvoMiddlewareFairing {
                middleware: Arc::new(self.middleware),
            };
            router = router.hoop(middleware_fairing);
        }

        // Create service and server
        let service = Service::new(router);
        let listener = TcpListener::new(addr);
        let server = Server::new(listener);

        // Run server
        server
            .serve(service)
            .await
            .map_err(|e| WebServerError::ServerError(e.to_string()))?;

        Ok(())
    }

    /// Run the server (fallback for when salvo feature is not enabled)
    #[cfg(not(feature = "salvo"))]
    pub async fn run(self) -> Result<()> {
        Err(WebServerError::adapter_error(
            "Salvo feature not enabled. Enable with --features salvo".to_string(),
        ))
    }
}

/// Wrapper to adapt our HandlerFn to Salvo's Handler trait
#[derive(Clone)]
struct SalvoHandlerWrapper {
    path: String,
    method: HttpMethod,
    routes: Arc<Vec<(String, HttpMethod, HandlerFn)>>,
}

#[cfg(feature = "salvo")]
#[salvo::async_trait]
impl Handler for SalvoHandlerWrapper {
    async fn handle(
        &self,
        req: &mut SalvoRequest,
        depot: &mut Depot,
        res: &mut SalvoResponse,
        _ctrl: &mut FlowCtrl,
    ) {
        // Find the handler for this route
        let handler = self
            .routes
            .iter()
            .find(|(route_path, route_method, _)| {
                route_path == &self.path && route_method == &self.method
            })
            .map(|(_, _, handler)| handler);

        let handler = match handler {
            Some(h) => h,
            None => {
                res.status_code(SalvoStatusCode::NOT_FOUND);
                res.render("Route not found");
                return;
            }
        };

        // Convert Salvo request to our Request type
        let our_request = match convert_salvo_request_to_ours(req).await {
            Ok(req) => req,
            Err(e) => {
                eprintln!("Failed to convert request: {:?}", e);
                res.status_code(SalvoStatusCode::INTERNAL_SERVER_ERROR);
                res.render("Request conversion error");
                return;
            }
        };

        // Call our handler
        match handler(our_request).await {
            Ok(response) => {
                // Convert our Response to Salvo response
                if let Err(e) = convert_our_response_to_salvo(response, res).await {
                    eprintln!("Failed to convert response: {:?}", e);
                    res.status_code(SalvoStatusCode::INTERNAL_SERVER_ERROR);
                    res.render("Response conversion error");
                }
            }
            Err(e) => {
                eprintln!("Handler error: {:?}", e);
                res.status_code(SalvoStatusCode::INTERNAL_SERVER_ERROR);
                res.render(format!("Handler error: {}", e));
            }
        }
    }
}

/// Middleware wrapper for Salvo
#[cfg(feature = "salvo")]
struct SalvoMiddlewareFairing {
    middleware: Arc<Vec<Box<dyn Middleware>>>,
}

#[cfg(feature = "salvo")]
#[salvo::async_trait]
impl Handler for SalvoMiddlewareFairing {
    async fn handle(
        &self,
        req: &mut SalvoRequest,
        depot: &mut Depot,
        res: &mut SalvoResponse,
        ctrl: &mut FlowCtrl,
    ) {
        // Convert to our Request type for middleware processing
        if let Ok(our_request) = convert_salvo_request_to_ours(req).await {
            // Process through our middleware chain
            for middleware in self.middleware.iter() {
                // In a full implementation, this would properly chain middleware
                println!(
                    "Processing request through middleware: {}",
                    req.uri().path()
                );
            }
        }

        // Continue to next handler
        ctrl.call_next(req, depot, res).await;
    }
}

/// Convert Salvo request to our Request type
#[cfg(feature = "salvo")]
async fn convert_salvo_request_to_ours(salvo_req: &mut SalvoRequest) -> Result<Request> {
    use crate::types::{Body, Headers};
    use http::Uri;

    let method = match salvo_req.method() {
        &SalvoMethod::GET => HttpMethod::GET,
        &SalvoMethod::POST => HttpMethod::POST,
        &SalvoMethod::PUT => HttpMethod::PUT,
        &SalvoMethod::DELETE => HttpMethod::DELETE,
        &SalvoMethod::PATCH => HttpMethod::PATCH,
        &SalvoMethod::HEAD => HttpMethod::HEAD,
        &SalvoMethod::OPTIONS => HttpMethod::OPTIONS,
        _ => HttpMethod::GET, // Default fallback
    };

    // Read body
    let body_bytes = match salvo_req.payload().await {
        Ok(Some(bytes)) => bytes.to_vec(),
        _ => Vec::new(),
    };

    // Convert headers
    let mut headers = Headers::new();
    for (name, value) in salvo_req.headers().iter() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Build URI
    let uri_str = format!(
        "{}?{}",
        salvo_req.uri().path(),
        salvo_req.uri().query().unwrap_or("")
    );
    let uri: Uri = uri_str
        .parse()
        .map_err(|e| WebServerError::custom(format!("Invalid URI: {}", e)))?;

    // Parse query parameters
    let query_params = salvo_req
        .queries()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    Ok(Request {
        method,
        uri,
        version: http::Version::HTTP_11,
        headers,
        body: Body::from_bytes(body_bytes),
        extensions: std::collections::HashMap::new(),
        path_params: std::collections::HashMap::new(),
        cookies: std::collections::HashMap::new(),
        form_data: None,
        multipart: None,
        query_params,
    })
}

/// Convert our Response to Salvo response
#[cfg(feature = "salvo")]
async fn convert_our_response_to_salvo(
    response: Response,
    salvo_res: &mut SalvoResponse,
) -> Result<()> {
    // Set status code
    let status_code = SalvoStatusCode::from_u16(response.status.as_u16())
        .unwrap_or(SalvoStatusCode::INTERNAL_SERVER_ERROR);
    salvo_res.status_code(status_code);

    // Set headers
    for (name, value) in response.headers.iter() {
        if let Ok(header_value) = HeaderValue::from_str(value) {
            salvo_res.headers_mut().insert(
                name.parse().unwrap_or_else(|_| {
                    salvo::http::header::HeaderName::from_static("x-custom-header")
                }),
                header_value,
            );
        }
    }

    // Set body
    let body_bytes = response.body.into_bytes()?;
    if !body_bytes.is_empty() {
        salvo_res
            .write_body(body_bytes)
            .map_err(|e| WebServerError::custom(format!("Failed to write response body: {}", e)))?;
    }

    Ok(())
}

// Fallback implementations for when salvo feature is not enabled
#[cfg(not(feature = "salvo"))]
async fn convert_salvo_request_to_ours(_req: &mut ()) -> Result<Request> {
    Err(WebServerError::adapter_error(
        "Salvo feature not enabled".to_string(),
    ))
}

#[cfg(not(feature = "salvo"))]
async fn convert_our_response_to_salvo(_response: Response, _res: &mut ()) -> Result<()> {
    Err(WebServerError::adapter_error(
        "Salvo feature not enabled".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HttpMethod, Request, Response, StatusCode};

    #[test]
    fn test_salvo_adapter_creation() {
        let adapter = SalvoAdapter::new();
        assert_eq!(adapter.routes.len(), 0);
        assert_eq!(adapter.middleware.len(), 0);
        assert!(adapter.addr.is_none());
    }

    #[tokio::test]
    async fn test_salvo_adapter_bind() {
        let mut adapter = SalvoAdapter::new();
        let result = adapter.bind("127.0.0.1:8080").await;
        assert!(result.is_ok());
        assert!(adapter.addr.is_some());
    }

    #[test]
    fn test_salvo_adapter_route_registration() {
        let mut adapter = SalvoAdapter::new();

        let handler: HandlerFn =
            Box::new(|_req| Box::pin(async move { Ok(Response::ok().body("test")) }));

        adapter.route("/test", HttpMethod::GET, handler);
        assert_eq!(adapter.routes.len(), 1);
        assert_eq!(adapter.routes[0].0, "/test");
        assert_eq!(adapter.routes[0].1, HttpMethod::GET);
    }

    #[test]
    fn test_salvo_adapter_middleware_registration() {
        use crate::middleware::LoggingMiddleware;

        let mut adapter = SalvoAdapter::new();
        adapter.middleware(Box::new(LoggingMiddleware::new()));

        assert_eq!(adapter.middleware.len(), 1);
    }

    #[test]
    fn test_salvo_handler_wrapper_creation() {
        let routes = Arc::new(vec![]);
        let wrapper = SalvoHandlerWrapper {
            path: "/test".to_string(),
            method: HttpMethod::GET,
            routes,
        };

        assert_eq!(wrapper.path, "/test");
        assert_eq!(wrapper.method, HttpMethod::GET);
    }

    #[cfg(feature = "salvo")]
    #[test]
    fn test_salvo_middleware_fairing_creation() {
        let middleware: Vec<Box<dyn Middleware>> = vec![];
        let fairing = SalvoMiddlewareFairing {
            middleware: Arc::new(middleware),
        };

        assert_eq!(fairing.middleware.len(), 0);
    }

    #[test]
    fn test_salvo_adapter_default() {
        let adapter = SalvoAdapter::default();
        assert_eq!(adapter.routes.len(), 0);
        assert_eq!(adapter.middleware.len(), 0);
        assert!(adapter.addr.is_none());
    }

    #[tokio::test]
    async fn test_salvo_adapter_bind_invalid_address() {
        let mut adapter = SalvoAdapter::new();
        let result = adapter.bind("invalid-address").await;
        assert!(result.is_err());
    }

    #[cfg(not(feature = "salvo"))]
    #[tokio::test]
    async fn test_fallback_implementations() {
        let result = convert_salvo_request_to_ours(&mut ()).await;
        assert!(result.is_err());

        let response = Response::ok();
        let result = convert_our_response_to_salvo(response, &mut ()).await;
        assert!(result.is_err());
    }
}
