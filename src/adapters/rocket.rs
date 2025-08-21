//! Rocket framework adapter.

use crate::core::{HandlerFn, Middleware};
use crate::error::{Result, WebServerError};
use crate::types::{HttpMethod, Request, Response};
use rocket::{
    http::{Method, Status},
    route::{Handler as RocketHandler, Outcome},
    Data, Route, State,
};
use std::net::SocketAddr;

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
    pub async fn run(self) -> Result<()> {
        let addr = self
            .addr
            .ok_or_else(|| WebServerError::BindError("Server not bound to address".to_string()))?;

        // Build Rocket configuration
        let config = rocket::Config {
            port: addr.port(),
            address: addr.ip(),
            ..Default::default()
        };

        // Create Rocket instance
        let mut rocket_builder = rocket::custom(&config);

        // Add routes
        for (path, method, handler) in self.routes {
            let rocket_method = convert_method(method);
            let route = Route::new(rocket_method, &path, RocketHandlerWrapper { handler });
            rocket_builder = rocket_builder.mount("/", vec![route]);
        }

        // Launch Rocket
        rocket_builder
            .launch()
            .await
            .map_err(|e| WebServerError::ServerError(e.to_string()))?;

        Ok(())
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
    let body_bytes = response.body.into_bytes();
    if !body_bytes.is_empty() {
        rocket_response.sized_body(body_bytes.len(), Cursor::new(body_bytes));
    }

    Ok(rocket_response.finalize())
}
