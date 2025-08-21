//! Poem framework adapter.

use crate::core::{HandlerFn, Middleware};
use crate::error::{Result, WebServerError};
use crate::types::{HttpMethod, Request, Response};
use poem::{
    endpoint::Endpoint,
    http::{Method, StatusCode},
    listener::TcpListener,
    middleware::Tracing,
    web::Data,
    Body, IntoResponse, Route, Server,
};
use std::net::SocketAddr;

/// Poem framework adapter
pub struct PoemAdapter {
    routes: Vec<(String, HttpMethod, HandlerFn)>,
    middleware: Vec<Box<dyn Middleware>>,
    addr: Option<SocketAddr>,
}

impl Default for PoemAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl PoemAdapter {
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

        // Create Poem routes
        let mut app = Route::new();

        // Add routes
        for (path, method, handler) in self.routes {
            let poem_handler = PoemHandlerWrapper { handler };

            match method {
                HttpMethod::GET => {
                    app = app.at(&path, poem::get(poem_handler));
                }
                HttpMethod::POST => {
                    app = app.at(&path, poem::post(poem_handler));
                }
                HttpMethod::PUT => {
                    app = app.at(&path, poem::put(poem_handler));
                }
                HttpMethod::DELETE => {
                    app = app.at(&path, poem::delete(poem_handler));
                }
                HttpMethod::PATCH => {
                    app = app.at(&path, poem::patch(poem_handler));
                }
                HttpMethod::HEAD => {
                    app = app.at(&path, poem::head(poem_handler));
                }
                HttpMethod::OPTIONS => {
                    app = app.at(&path, poem::options(poem_handler));
                }
            }
        }

        // Add tracing middleware
        let app = app.with(Tracing);

        // Create and run server
        Server::new(TcpListener::bind(addr))
            .run(app)
            .await
            .map_err(|e| WebServerError::ServerError(e.to_string()))?;

        Ok(())
    }
}

/// Wrapper to adapt our HandlerFn to Poem's endpoint
#[derive(Clone)]
struct PoemHandlerWrapper {
    handler: HandlerFn,
}

impl Endpoint for PoemHandlerWrapper {
    type Output = poem::Result<poem::Response>;

    async fn call(&self, req: poem::Request) -> Self::Output {
        // Convert Poem request to our Request type
        let our_request = match convert_request(req).await {
            Ok(req) => req,
            Err(e) => {
                eprintln!("Failed to convert request: {:?}", e);
                return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };

        // Call our handler
        match (self.handler)(our_request).await {
            Ok(response) => {
                // Convert our Response to Poem response
                match convert_response(response) {
                    Ok(poem_response) => Ok(poem_response),
                    Err(e) => {
                        eprintln!("Failed to convert response: {:?}", e);
                        Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
                    }
                }
            }
            Err(e) => {
                eprintln!("Handler error: {:?}", e);
                Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        }
    }
}

/// Convert Poem request to our Request type
async fn convert_request(poem_req: poem::Request) -> Result<Request> {
    let (parts, body) = poem_req.into_parts();

    let method = match parts.method {
        Method::GET => HttpMethod::GET,
        Method::POST => HttpMethod::POST,
        Method::PUT => HttpMethod::PUT,
        Method::DELETE => HttpMethod::DELETE,
        Method::PATCH => HttpMethod::PATCH,
        Method::HEAD => HttpMethod::HEAD,
        Method::OPTIONS => HttpMethod::OPTIONS,
        _ => HttpMethod::GET, // Default fallback
    };

    // Read body
    let body_bytes = match body.into_bytes().await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => Vec::new(),
    };

    let mut headers = crate::types::Headers::new();
    for (name, value) in parts.headers.iter() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    let query_params = parts
        .uri
        .query()
        .unwrap_or("")
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
        path: parts.uri.path().to_string(),
        headers,
        body: crate::types::Body::from_bytes(body_bytes),
        query_params,
    })
}

/// Convert our Response to Poem response
fn convert_response(response: Response) -> Result<poem::Response> {
    let mut poem_response = poem::Response::builder();

    // Set status
    poem_response = poem_response.status(
        StatusCode::from_u16(response.status.0).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
    );

    // Set headers
    for (key, value) in response.headers.iter() {
        if let (Ok(name), Ok(value)) = (
            key.parse::<poem::http::HeaderName>(),
            value.parse::<poem::http::HeaderValue>(),
        ) {
            poem_response = poem_response.header(name, value);
        }
    }

    // Set body
    let body_bytes = response.body.into_bytes();
    let body = if body_bytes.is_empty() {
        Body::empty()
    } else {
        Body::from_bytes(body_bytes)
    };

    poem_response
        .body(body)
        .map_err(|e| WebServerError::ResponseError(e.to_string()))
}
