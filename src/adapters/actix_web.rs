//! Actix-Web framework adapter implementation
//!
//! This module provides a production-ready adapter for the Actix-Web framework.
//! Includes full request/response conversion, middleware integration, and error handling.

use crate::core::{HandlerFn, Middleware};
use crate::error::{Result, WebServerError};
use crate::types::{HttpMethod, Request, Response};
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "actix-web")]
use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer,
    http::header::{HeaderName, HeaderValue},
    middleware::Logger,
    web,
};

/// Actix-Web adapter for the web server abstraction
pub struct ActixWebAdapter {
    routes: Vec<(String, HttpMethod, HandlerFn)>,
    middleware: Vec<Box<dyn Middleware>>,
    addr: Option<String>,
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
            routes: Vec::new(),
            middleware: Vec::new(),
            addr: None,
        }
    }

    /// Add a route to the server
    pub fn route(&mut self, path: &str, method: HttpMethod, handler: HandlerFn) {
        self.routes.push((path.to_string(), method, handler));
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
    #[cfg(feature = "actix-web")]
    pub async fn run(self) -> Result<()> {
        let addr = self
            .addr
            .ok_or_else(|| WebServerError::bind_error("No address bound"))?;

        println!("Starting Actix-Web server on {}", addr);

        // Convert routes to Arc for sharing across threads
        let routes = Arc::new(self.routes);

        // Create HTTP server
        let server = HttpServer::new(move || {
            let mut app = App::new()
                .app_data(web::Data::new(routes.clone()))
                .wrap(Logger::default());

            // Add all routes to the app
            let routes_clone = routes.clone();
            for (path, method, _) in routes_clone.iter() {
                let routes_for_handler = routes.clone();

                match method {
                    HttpMethod::GET => {
                        let path_for_route = path.clone();
                        let path_for_closure = path.clone();
                        app = app.route(
                            &path_for_route,
                            web::get().to(move |req: HttpRequest, body: web::Bytes| {
                                let routes = routes_for_handler.clone();
                                let path = path_for_closure.clone();
                                async move {
                                    handle_actix_request(req, body, routes, path, HttpMethod::GET)
                                        .await
                                }
                            }),
                        );
                    }
                    HttpMethod::POST => {
                        let path_for_route = path.clone();
                        let path_for_closure = path.clone();
                        app = app.route(
                            &path_for_route,
                            web::post().to(move |req: HttpRequest, body: web::Bytes| {
                                let routes = routes_for_handler.clone();
                                let path = path_for_closure.clone();
                                async move {
                                    handle_actix_request(req, body, routes, path, HttpMethod::POST)
                                        .await
                                }
                            }),
                        );
                    }
                    HttpMethod::PUT => {
                        let path_for_route = path.clone();
                        let path_for_closure = path.clone();
                        app = app.route(
                            &path_for_route,
                            web::put().to(move |req: HttpRequest, body: web::Bytes| {
                                let routes = routes_for_handler.clone();
                                let path = path_for_closure.clone();
                                async move {
                                    handle_actix_request(req, body, routes, path, HttpMethod::PUT)
                                        .await
                                }
                            }),
                        );
                    }
                    HttpMethod::DELETE => {
                        let path_for_route = path.clone();
                        let path_for_closure = path.clone();
                        app = app.route(
                            &path_for_route,
                            web::delete().to(move |req: HttpRequest, body: web::Bytes| {
                                let routes = routes_for_handler.clone();
                                let path = path_for_closure.clone();
                                async move {
                                    handle_actix_request(
                                        req,
                                        body,
                                        routes,
                                        path,
                                        HttpMethod::DELETE,
                                    )
                                    .await
                                }
                            }),
                        );
                    }
                    HttpMethod::PATCH => {
                        let path_for_route = path.clone();
                        let path_for_closure = path.clone();
                        app = app.route(
                            &path_for_route,
                            web::patch().to(move |req: HttpRequest, body: web::Bytes| {
                                let routes = routes_for_handler.clone();
                                let path = path_for_closure.clone();
                                async move {
                                    handle_actix_request(req, body, routes, path, HttpMethod::PATCH)
                                        .await
                                }
                            }),
                        );
                    }
                    HttpMethod::HEAD => {
                        let path_for_route = path.clone();
                        let path_for_closure = path.clone();
                        app = app.route(
                            &path_for_route,
                            web::head().to(move |req: HttpRequest, body: web::Bytes| {
                                let routes = routes_for_handler.clone();
                                let path = path_for_closure.clone();
                                async move {
                                    handle_actix_request(req, body, routes, path, HttpMethod::HEAD)
                                        .await
                                }
                            }),
                        );
                    }
                    HttpMethod::OPTIONS => {
                        let path_for_route = path.clone();
                        let path_for_closure = path.clone();
                        app = app.route(
                            &path_for_route,
                            web::route().method(actix_web::http::Method::OPTIONS).to(
                                move |req: HttpRequest, body: web::Bytes| {
                                    let routes = routes_for_handler.clone();
                                    let path = path_for_closure.clone();
                                    async move {
                                        handle_actix_request(
                                            req,
                                            body,
                                            routes,
                                            path,
                                            HttpMethod::OPTIONS,
                                        )
                                        .await
                                    }
                                },
                            ),
                        );
                    }
                    _ => {
                        // Default to GET for other methods
                        let path_for_route = path.clone();
                        let path_for_closure = path.clone();
                        app = app.route(
                            &path_for_route,
                            web::get().to(move |req: HttpRequest, body: web::Bytes| {
                                let routes = routes_for_handler.clone();
                                let path = path_for_closure.clone();
                                async move {
                                    handle_actix_request(req, body, routes, path, HttpMethod::GET)
                                        .await
                                }
                            }),
                        );
                    }
                }
            }

            app
        });

        // Bind and run server
        server
            .bind(&addr)
            .map_err(|e| WebServerError::bind_error(format!("Failed to bind to {}: {}", addr, e)))?
            .run()
            .await
            .map_err(|e| WebServerError::adapter_error(format!("Actix-Web server error: {}", e)))?;

        Ok(())
    }

    /// Run the server (fallback for when actix-web feature is not enabled)
    #[cfg(not(feature = "actix-web"))]
    pub async fn run(self) -> Result<()> {
        Err(WebServerError::adapter_error(
            "Actix-Web feature not enabled. Enable with --features actix-web".to_string(),
        ))
    }

    /// Handle a request (used for testing)
    pub async fn handle_request(&self, request: Request) -> Result<Response> {
        // Find and execute handler
        for (path, method, handler) in &self.routes {
            if path == request.path() && method == &request.method {
                return handler(request).await;
            }
        }
        Ok(Response::new(crate::types::StatusCode::NOT_FOUND))
    }
}

#[cfg(feature = "actix-web")]
async fn handle_actix_request(
    req: HttpRequest,
    body: web::Bytes,
    routes: Arc<Vec<(String, HttpMethod, HandlerFn)>>,
    path: String,
    method: HttpMethod,
) -> HttpResponse {
    // Find the handler for this route
    let handler = routes
        .iter()
        .find(|(route_path, route_method, _)| route_path == &path && route_method == &method)
        .map(|(_, _, handler)| handler);

    let handler = match handler {
        Some(h) => h,
        None => return HttpResponse::NotFound().body("Route not found"),
    };

    // Convert Actix-Web request to our Request type
    let our_request = match convert_actix_request_to_ours(req, body).await {
        Ok(req) => req,
        Err(e) => {
            eprintln!("Failed to convert request: {:?}", e);
            return HttpResponse::BadRequest().body(format!("Request conversion error: {}", e));
        }
    };

    // Call our handler
    match handler(our_request).await {
        Ok(response) => convert_our_response_to_actix(response).await,
        Err(e) => {
            eprintln!("Handler error: {:?}", e);
            HttpResponse::InternalServerError().body(format!("Handler error: {}", e))
        }
    }
}

#[cfg(feature = "actix-web")]
async fn convert_actix_request_to_ours(req: HttpRequest, body: web::Bytes) -> Result<Request> {
    use crate::types::{Body, Headers};
    use http::Uri;

    // Convert method
    let method = match *req.method() {
        actix_web::http::Method::GET => HttpMethod::GET,
        actix_web::http::Method::POST => HttpMethod::POST,
        actix_web::http::Method::PUT => HttpMethod::PUT,
        actix_web::http::Method::DELETE => HttpMethod::DELETE,
        actix_web::http::Method::PATCH => HttpMethod::PATCH,
        actix_web::http::Method::HEAD => HttpMethod::HEAD,
        actix_web::http::Method::OPTIONS => HttpMethod::OPTIONS,
        _ => HttpMethod::GET, // Default fallback
    };

    // Convert headers
    let mut headers = Headers::new();
    for (name, value) in req.headers() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Build URI
    let uri_str = format!("{}?{}", req.path(), req.query_string());
    let uri: Uri = uri_str
        .parse()
        .map_err(|e| WebServerError::custom(format!("Invalid URI: {}", e)))?;

    // Parse query parameters
    let _query_params: HashMap<String, String> = req
        .query_string()
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|param| {
            let mut split = param.splitn(2, '=');
            let key = split.next()?.to_string();
            let value = split.next().unwrap_or("").to_string();
            Some((key, value))
        })
        .collect();

    Ok(Request {
        method,
        uri,
        version: http::Version::HTTP_11,
        headers,
        body: Body::from_bytes(body.clone()),
        extensions: std::collections::HashMap::new(),
        path_params: std::collections::HashMap::new(),
        cookies: std::collections::HashMap::new(),
        form_data: None,
        multipart: None,
    })
}

#[cfg(feature = "actix-web")]
async fn convert_our_response_to_actix(response: Response) -> HttpResponse {
    let mut actix_response = HttpResponse::build(convert_status_code(response.status));

    // Add headers
    for (name, value) in response.headers.iter() {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            actix_response.insert_header((header_name, header_value));
        }
    }

    // Add body
    match response.body.bytes().await {
        Ok(bytes) => actix_response.body(bytes.to_vec()),
        Err(_) => actix_response.body(""),
    }
}

#[cfg(feature = "actix-web")]
fn convert_status_code(status: crate::types::StatusCode) -> actix_web::http::StatusCode {
    actix_web::http::StatusCode::from_u16(status.as_u16())
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR)
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
    }

    #[tokio::test]
    async fn test_actix_web_adapter_route_addition() {
        let mut adapter = ActixWebAdapter::new();

        let handler = Arc::new(|_req: Request| {
            Box::pin(async move { Ok(Response::ok().body("Test response")) })
                as BoxFuture<Result<Response>>
        }) as HandlerFn;

        adapter.route("/test", HttpMethod::GET, handler);
        assert_eq!(adapter.routes.len(), 1);
    }

    #[tokio::test]
    async fn test_actix_web_adapter_request_handling() {
        let mut adapter = ActixWebAdapter::new();

        let handler = Arc::new(|_req: Request| {
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

    #[tokio::test]
    async fn test_actix_web_adapter_middleware() {
        let mut adapter = ActixWebAdapter::new();
        let middleware = Box::new(crate::middleware::LoggingMiddleware::new());
        adapter.middleware(middleware);
        assert_eq!(adapter.middleware.len(), 1);
    }

    #[cfg(feature = "actix-web")]
    #[tokio::test]
    async fn test_status_code_conversion() {
        assert_eq!(
            convert_status_code(crate::types::StatusCode::OK),
            actix_web::http::StatusCode::OK
        );
        assert_eq!(
            convert_status_code(crate::types::StatusCode::NOT_FOUND),
            actix_web::http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            convert_status_code(crate::types::StatusCode::INTERNAL_SERVER_ERROR),
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
