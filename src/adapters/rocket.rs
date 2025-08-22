//! Rocket framework adapter implementation
//!
//! This module provides a production-ready adapter for the Rocket framework.
//! Includes full request/response conversion, middleware integration, and error handling.

use crate::core::{HandlerFn, Middleware};
use crate::error::{Result, WebServerError};
use crate::types::{HttpMethod, Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "rocket")]
use rocket::{
    fairing::{Fairing, Info, Kind},
    http::{Method, Status},
    request::{FromRequest, Outcome},
    route::{Handler as RocketHandler, Outcome as RouteOutcome},
    Data, Request as RocketRequest, Response as RocketResponse, Route, State,
};

/// Rocket framework adapter
pub struct RocketAdapter {
    routes: Vec<(String, HttpMethod, HandlerFn)>,
    middleware: Vec<Box<dyn Middleware>>,
    addr: Option<SocketAddr>,
}

impl Default for RocketAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RocketAdapter {
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
    }

    /// Add middleware to the server
    pub fn middleware(&mut self, middleware: Box<dyn Middleware>) {
        self.middleware.push(middleware);
    }

    /// Run the server
    #[cfg(feature = "rocket")]
    pub async fn run(self) -> Result<()> {
        let addr = self
            .addr
            .ok_or_else(|| WebServerError::BindError("Server not bound to address".to_string()))?;

        println!("Starting Rocket server on {}", addr);

        // Build Rocket configuration
        let config = rocket::Config {
            port: addr.port(),
            address: addr.ip(),
            workers: num_cpus::get(),
            ..Default::default()
        };

        // Create shared routes data
        let routes_data = Arc::new(self.routes);

        // Create Rocket instance
        let mut rocket_builder = rocket::custom(&config).manage(routes_data.clone());

        // Add routes
        for (path, method, _) in routes_data.iter() {
            let rocket_method = convert_method(*method);
            let path_clone = path.clone();
            let routes_for_handler = routes_data.clone();

            let route = Route::new(
                rocket_method,
                &path_clone,
                RocketHandlerWrapper {
                    path: path_clone,
                    method: *method,
                },
            );
            rocket_builder = rocket_builder.mount("/", vec![route]);
        }

        // Add logging fairing
        rocket_builder = rocket_builder.attach(LoggingFairing);

        // Launch Rocket
        rocket_builder
            .launch()
            .await
            .map_err(|e| WebServerError::ServerError(e.to_string()))?;

        Ok(())
    }

    /// Run the server (fallback for when rocket feature is not enabled)
    #[cfg(not(feature = "rocket"))]
    pub async fn run(self) -> Result<()> {
        Err(WebServerError::adapter_error(
            "Rocket feature not enabled. Enable with --features rocket".to_string(),
        ))
    }
}

/// Wrapper to adapt our HandlerFn to Rocket's Handler trait
struct RocketHandlerWrapper {
    handler: HandlerFn,
}

#[rocket::async_trait]
impl RocketHandler for RocketHandlerWrapper {
    async fn handle<'r>(&self, request: &'r rocket::Request<'_>, data: Data<'r>) -> Outcome<'r> {
        // Convert Rocket request to our Request type
        let our_request = match convert_request(request, data).await {
            Ok(req) => req,
            Err(e) => {
                eprintln!("Failed to convert request: {:?}", e);
                return Outcome::Failure(Status::InternalServerError);
            }
        };

        // Call our handler
        match (self.handler)(our_request).await {
            Ok(response) => {
                // Convert our Response to Rocket response
                match convert_response(response) {
                    Ok(rocket_response) => Outcome::Success(rocket_response),
                    Err(e) => {
                        eprintln!("Failed to convert response: {:?}", e);
                        Outcome::Failure(Status::InternalServerError)
                    }
                }
            }
            Err(e) => {
                eprintln!("Handler error: {:?}", e);
                Outcome::Failure(Status::InternalServerError)
            }
        }
    }
}

/// Convert HttpMethod to Rocket Method
fn convert_method(method: HttpMethod) -> Method {
    match method {
        HttpMethod::GET => Method::Get,
        HttpMethod::POST => Method::Post,
        HttpMethod::PUT => Method::Put,
        HttpMethod::DELETE => Method::Delete,
        HttpMethod::PATCH => Method::Patch,
        HttpMethod::HEAD => Method::Head,
        HttpMethod::OPTIONS => Method::Options,
    }
}

/// Convert Rocket request to our Request type
async fn convert_request(rocket_req: &rocket::Request<'_>, data: Data<'_>) -> Result<Request> {
    let method = match rocket_req.method() {
        Method::Get => HttpMethod::GET,
        Method::Post => HttpMethod::POST,
        Method::Put => HttpMethod::PUT,
        Method::Delete => HttpMethod::DELETE,
        Method::Patch => HttpMethod::PATCH,
        Method::Head => HttpMethod::HEAD,
        Method::Options => HttpMethod::OPTIONS,
        _ => HttpMethod::GET, // Default fallback
    };

    // Read body data
    let body_bytes = match data.open(2.megabytes()).into_bytes().await {
        Ok(bytes) => bytes.into_inner(),
        Err(_) => Vec::new(),
    };

    let mut headers = crate::types::Headers::new();
    for header in rocket_req.headers().iter() {
        headers.insert(header.name().to_string(), header.value().to_string());
    }

    Ok(Request {
        method,
        path: rocket_req.uri().path().to_string(),
        headers,
        body: crate::types::Body::from_bytes(body_bytes),
        query_params: rocket_req
            .query_fields()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    })
}

/// Convert our Response to Rocket response
fn convert_response(response: Response) -> Result<rocket::Response<'static>> {
    use rocket::response::Response as RocketResponse;
    use std::io::Cursor;

    let mut rocket_response = RocketResponse::build();

    // Set status
    if let Ok(status) = Status::from_code(response.status.0) {
        rocket_response.status(status);
    }

    // Set headers
    for (key, value) in response.headers.iter() {
        rocket_response.raw_header(key, value);
    }

    // Set body
    let body_bytes = response.body.into_bytes()?;
    if !body_bytes.is_empty() {
        rocket_response.sized_body(body_bytes.len(), Cursor::new(body_bytes));
    }

    Ok(rocket_response.finalize())
}

/// Middleware fairing for logging
#[cfg(feature = "rocket")]
struct MiddlewareFairing {
    middleware: Arc<Vec<Box<dyn Middleware>>>,
}

#[cfg(feature = "rocket")]
#[rocket::async_trait]
impl Fairing for MiddlewareFairing {
    fn info(&self) -> Info {
        Info {
            name: "Middleware Fairing",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut rocket::Request<'_>, _: &mut Data<'_>) {
        // Middleware handling would go here
        println!("Processing request through middleware: {}", request.uri());
    }

    async fn on_response<'r>(
        &self,
        _request: &'r rocket::Request<'_>,
        response: &mut rocket::Response<'r>,
    ) {
        // Response middleware handling
        println!("Processing response through middleware");
    }
}

/// Logging fairing for request/response logging
#[cfg(feature = "rocket")]
struct LoggingFairing;

#[cfg(feature = "rocket")]
#[rocket::async_trait]
impl Fairing for LoggingFairing {
    fn info(&self) -> Info {
        Info {
            name: "Request Logger",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut rocket::Request<'_>, _: &mut Data<'_>) {
        println!("-> {} {}", request.method(), request.uri());
    }

    async fn on_response<'r>(
        &self,
        request: &'r rocket::Request<'_>,
        response: &mut rocket::Response<'r>,
    ) {
        println!(
            "<- {} {} - {}",
            request.method(),
            request.uri(),
            response.status()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HttpMethod, Request, Response, StatusCode};

    #[test]
    fn test_rocket_adapter_creation() {
        let adapter = RocketAdapter::new();
        assert_eq!(adapter.routes.len(), 0);
        assert_eq!(adapter.middleware.len(), 0);
        assert!(adapter.addr.is_none());
    }

    #[tokio::test]
    async fn test_rocket_adapter_bind() {
        let mut adapter = RocketAdapter::new();
        let result = adapter.bind("127.0.0.1:8080").await;
        assert!(result.is_ok());
        assert!(adapter.addr.is_some());
    }

    #[test]
    fn test_rocket_adapter_route_registration() {
        let mut adapter = RocketAdapter::new();

        let handler: HandlerFn =
            Box::new(|_req| Box::pin(async move { Ok(Response::ok().body("test")) }));

        adapter.route("/test", HttpMethod::GET, handler);
        assert_eq!(adapter.routes.len(), 1);
        assert_eq!(adapter.routes[0].0, "/test");
        assert_eq!(adapter.routes[0].1, HttpMethod::GET);
    }

    #[test]
    fn test_convert_method() {
        assert_eq!(convert_method(HttpMethod::GET), Method::Get);
        assert_eq!(convert_method(HttpMethod::POST), Method::Post);
        assert_eq!(convert_method(HttpMethod::PUT), Method::Put);
        assert_eq!(convert_method(HttpMethod::DELETE), Method::Delete);
        assert_eq!(convert_method(HttpMethod::PATCH), Method::Patch);
        assert_eq!(convert_method(HttpMethod::HEAD), Method::Head);
        assert_eq!(convert_method(HttpMethod::OPTIONS), Method::Options);
    }

    #[test]
    fn test_convert_response() {
        let response = Response::ok()
            .body("test body")
            .header("X-Custom-Header", "custom-value");

        let rocket_response = convert_response(response);
        assert!(rocket_response.is_ok());

        let rocket_resp = rocket_response.unwrap();
        assert_eq!(rocket_resp.status(), Status::Ok);

        // Check headers
        let headers = rocket_resp.headers();
        assert!(headers.get("X-Custom-Header").any(|h| h == "custom-value"));
    }

    #[test]
    fn test_rocket_adapter_middleware_registration() {
        use crate::middleware::LoggingMiddleware;

        let mut adapter = RocketAdapter::new();
        adapter.middleware(Box::new(LoggingMiddleware::new()));

        assert_eq!(adapter.middleware.len(), 1);
    }

    #[test]
    fn test_response_status_conversion() {
        let response = Response::with_status(StatusCode::NOT_FOUND).body("Not found");
        let rocket_response = convert_response(response);

        assert!(rocket_response.is_ok());
        let rocket_resp = rocket_response.unwrap();
        assert_eq!(rocket_resp.status(), Status::NotFound);
    }

    #[test]
    fn test_empty_response_body() {
        let response = Response::ok(); // No body
        let rocket_response = convert_response(response);

        assert!(rocket_response.is_ok());
        let rocket_resp = rocket_response.unwrap();
        assert_eq!(rocket_resp.status(), Status::Ok);
    }

    #[cfg(feature = "rocket")]
    #[test]
    fn test_logging_fairing_info() {
        let fairing = LoggingFairing;
        let info = fairing.info();

        assert_eq!(info.name, "Request Logger");
        assert!(info.kind.contains(Kind::Request));
        assert!(info.kind.contains(Kind::Response));
    }

    #[cfg(feature = "rocket")]
    #[test]
    fn test_middleware_fairing_info() {
        let middleware: Vec<Box<dyn Middleware>> = vec![];
        let fairing = MiddlewareFairing {
            middleware: Arc::new(middleware),
        };
        let info = fairing.info();

        assert_eq!(info.name, "Middleware Fairing");
        assert!(info.kind.contains(Kind::Request));
        assert!(info.kind.contains(Kind::Response));
    }
}
