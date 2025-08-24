//! Warp framework adapter.

use crate::core::{HandlerFn, Middleware};
use crate::error::{Result, WebServerError};
use crate::types::{Body, Headers, HttpMethod, Request, StatusCode};
use http::HeaderMap;
use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc};
use warp::{Filter, Reply, http::StatusCode as WarpStatusCode};

/// Warp framework adapter
pub struct WarpAdapter {
    routes: Vec<(String, HttpMethod, Arc<HandlerFn>)>,
    middleware: Vec<Box<dyn Middleware>>,
    addr: Option<SocketAddr>,
}

impl Default for WarpAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl WarpAdapter {
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            middleware: Vec::new(),
            addr: None,
        }
    }

    /// Bind the server to an address
    pub async fn bind(&mut self, addr: &str) -> Result<()> {
        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|e| WebServerError::bind_error(format!("Invalid address {}: {}", addr, e)))?;
        self.addr = Some(socket_addr);
        Ok(())
    }

    /// Run the server
    pub async fn run(self) -> Result<()> {
        let addr = self
            .addr
            .ok_or_else(|| WebServerError::bind_error("No address bound"))?;

        println!("Warp server starting on {}", addr);

        // Store routes for the handler to access
        let routes = Arc::new(self.routes);

        // Create a catch-all route that will route requests based on path and method
        let routes_filter = warp::any()
            .and(warp::method())
            .and(warp::path::full())
            .and(warp::header::headers_cloned())
            .and(warp::body::bytes())
            .and_then(
                move |method: warp::http::Method,
                      path: warp::path::FullPath,
                      headers: HeaderMap,
                      body: bytes::Bytes| {
                    let routes = Arc::clone(&routes);
                    async move {
                        handle_warp_request_with_routing(method, path, headers, body, routes).await
                    }
                },
            )
            .with(warp::log("web_server_abstraction"));

        warp::serve(routes_filter).run(addr).await;

        Ok(())
    }

    /// Add a route to the server
    pub fn route(&mut self, path: &str, method: HttpMethod, handler: HandlerFn) -> &mut Self {
        self.routes
            .push((path.to_string(), method, Arc::new(handler)));
        println!("Added Warp route: {:?} {}", method, path);
        self
    }

    /// Add middleware to the server
    pub fn middleware(&mut self, middleware: Box<dyn Middleware>) -> &mut Self {
        self.middleware.push(middleware);
        println!("Added middleware to Warp adapter");
        self
    }
}

/// Handle Warp request with proper routing
async fn handle_warp_request_with_routing(
    method: warp::http::Method,
    path: warp::path::FullPath,
    headers: HeaderMap,
    body: bytes::Bytes,
    routes: Arc<Vec<(String, HttpMethod, Arc<HandlerFn>)>>,
) -> std::result::Result<impl Reply, Infallible> {
    let path_str = path.as_str();

    // Convert Warp method to our HttpMethod
    let our_method = match method {
        warp::http::Method::GET => HttpMethod::GET,
        warp::http::Method::POST => HttpMethod::POST,
        warp::http::Method::PUT => HttpMethod::PUT,
        warp::http::Method::DELETE => HttpMethod::DELETE,
        warp::http::Method::PATCH => HttpMethod::PATCH,
        warp::http::Method::HEAD => HttpMethod::HEAD,
        warp::http::Method::OPTIONS => HttpMethod::OPTIONS,
        _ => HttpMethod::GET, // Default
    };

    // Find matching route
    let handler = routes
        .iter()
        .find(|(route_path, route_method, _)| route_path == path_str && *route_method == our_method)
        .map(|(_, _, handler)| Arc::clone(handler));

    if let Some(handler) = handler {
        // Convert to our Request type
        let our_request = match convert_warp_request_to_ours(headers, body).await {
            Ok(req) => req,
            Err(e) => {
                return Ok(warp::reply::with_status(
                    format!("Request conversion error: {}", e),
                    WarpStatusCode::BAD_REQUEST,
                ));
            }
        };

        // Call the actual handler
        match handler(our_request).await {
            Ok(response) => {
                // Extract the response body as a string for consistent typing
                let body_bytes = response.body.bytes().await.unwrap_or_default();
                let body_string = String::from_utf8_lossy(&body_bytes).to_string();

                // Convert status code
                let status = match response.status {
                    StatusCode::OK => WarpStatusCode::OK,
                    StatusCode::CREATED => WarpStatusCode::CREATED,
                    StatusCode::NOT_FOUND => WarpStatusCode::NOT_FOUND,
                    StatusCode::INTERNAL_SERVER_ERROR => WarpStatusCode::INTERNAL_SERVER_ERROR,
                    StatusCode::BAD_REQUEST => WarpStatusCode::BAD_REQUEST,
                    _ => WarpStatusCode::OK,
                };

                Ok(warp::reply::with_status(body_string, status))
            }
            Err(e) => Ok(warp::reply::with_status(
                format!("Handler error: {}", e),
                WarpStatusCode::INTERNAL_SERVER_ERROR,
            )),
        }
    } else {
        // No route found
        Ok(warp::reply::with_status(
            format!("Route not found: {} {}", method, path_str),
            WarpStatusCode::NOT_FOUND,
        ))
    }
}

/// Convert Warp request to our Request type
async fn convert_warp_request_to_ours(
    headers: HeaderMap,
    body: bytes::Bytes,
) -> Result<Request> {
    // For this basic implementation, we'll use defaults for some fields
    // In a full implementation, these would be extracted from the Warp request
    let method = HttpMethod::GET; // Would be extracted from the filter
    let uri = http::Uri::from_static("/"); // Would be extracted from the request

    // Convert headers
    let mut our_headers = Headers::new();
    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str() {
            our_headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Convert body
    let body = Body::from(body.to_vec());

    // Initialize other fields
    let extensions = HashMap::new();
    let path_params = HashMap::new();
    let cookies = HashMap::new();
    let form_data = None;
    let multipart = None;

    Ok(Request {
        method,
        uri,
        version: http::Version::HTTP_11, // Default version
        headers: our_headers,
        body,
        extensions,
        path_params,
        cookies,
        form_data,
        multipart,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Body, Headers, StatusCode};

    #[tokio::test]
    async fn test_warp_adapter_creation() {
        let adapter = WarpAdapter::new();
        assert!(adapter.routes.is_empty());
        assert!(adapter.middleware.is_empty());
        assert!(adapter.addr.is_none());
    }

    #[tokio::test]
    async fn test_warp_adapter_bind() {
        let mut adapter = WarpAdapter::new();
        let result = adapter.bind("127.0.0.1:0").await;
        assert!(result.is_ok());
        assert!(adapter.addr.is_some());
    }

    #[tokio::test]
    async fn test_response_conversion() {
        let response = Response {
            status: StatusCode::OK,
            headers: {
                let mut h = Headers::new();
                h.insert("content-type".to_string(), "application/json".to_string());
                h
            },
            body: Body::from("test response"),
        };

        // Test that we can create a response - the actual conversion is done inline now
        let body_bytes = response.body.bytes().await.unwrap_or_default();
        let body_string = String::from_utf8_lossy(&body_bytes).to_string();
        assert_eq!(body_string, "test response");
    }
}
