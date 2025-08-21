//! Salvo framework adapter.

use crate::core::{HandlerFn, Middleware};
use crate::error::{Result, WebServerError};
use crate::types::{HttpMethod, Request, Response};
use salvo::prelude::*;
use std::net::SocketAddr;

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

        // Create Salvo router
        let mut router = Router::new();

        // Add routes
        for (path, method, handler) in self.routes {
            let salvo_handler = SalvoHandlerWrapper { handler };

            match method {
                HttpMethod::GET => {
                    router = router.get(path, salvo_handler);
                }
                HttpMethod::POST => {
                    router = router.post(path, salvo_handler);
                }
                HttpMethod::PUT => {
                    router = router.put(path, salvo_handler);
                }
                HttpMethod::DELETE => {
                    router = router.delete(path, salvo_handler);
                }
                HttpMethod::PATCH => {
                    router = router.patch(path, salvo_handler);
                }
                HttpMethod::HEAD => {
                    router = router.head(path, salvo_handler);
                }
                HttpMethod::OPTIONS => {
                    router = router.options(path, salvo_handler);
                }
            }
        }

        // Create service and server
        let service = Service::new(router);
        let server = Server::new(TcpListener::new(addr).bind().await);

        // Run server
        server
            .serve(service)
            .await
            .map_err(|e| WebServerError::ServerError(e.to_string()))?;

        Ok(())
    }
}

/// Wrapper to adapt our HandlerFn to Salvo's Handler trait
#[derive(Clone)]
struct SalvoHandlerWrapper {
    handler: HandlerFn,
}

#[salvo::async_trait]
impl Handler for SalvoHandlerWrapper {
    async fn handle(
        &self,
        req: &mut salvo::Request,
        depot: &mut Depot,
        res: &mut salvo::Response,
        ctrl: &mut FlowCtrl,
    ) {
        // Convert Salvo request to our Request type
        let our_request = match convert_request(req).await {
            Ok(req) => req,
            Err(e) => {
                eprintln!("Failed to convert request: {:?}", e);
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                return;
            }
        };

        // Call our handler
        match (self.handler)(our_request).await {
            Ok(response) => {
                // Convert our Response to Salvo response
                if let Err(e) = convert_response(response, res).await {
                    eprintln!("Failed to convert response: {:?}", e);
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
            Err(e) => {
                eprintln!("Handler error: {:?}", e);
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }
}

/// Convert Salvo request to our Request type
async fn convert_request(salvo_req: &mut salvo::Request) -> Result<Request> {
    let method = match salvo_req.method() {
        &salvo::http::Method::GET => HttpMethod::GET,
        &salvo::http::Method::POST => HttpMethod::POST,
        &salvo::http::Method::PUT => HttpMethod::PUT,
        &salvo::http::Method::DELETE => HttpMethod::DELETE,
        &salvo::http::Method::PATCH => HttpMethod::PATCH,
        &salvo::http::Method::HEAD => HttpMethod::HEAD,
        &salvo::http::Method::OPTIONS => HttpMethod::OPTIONS,
        _ => HttpMethod::GET, // Default fallback
    };

    // Read body
    let body_bytes = match salvo_req.payload().await {
        Ok(Some(bytes)) => bytes.to_vec(),
        _ => Vec::new(),
    };

    let mut headers = crate::types::Headers::new();
    for (name, value) in salvo_req.headers().iter() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    let query_params = salvo_req
        .queries()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    Ok(Request {
        method,
        path: salvo_req.uri().path().to_string(),
        headers,
        body: crate::types::Body::from_bytes(body_bytes),
        query_params,
    })
}

/// Convert our Response to Salvo response
async fn convert_response(response: Response, salvo_res: &mut salvo::Response) -> Result<()> {
    // Set status
    salvo_res.status_code(
        StatusCode::from_u16(response.status.0).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
    );

    // Set headers
    for (key, value) in response.headers.iter() {
        if let (Ok(name), Ok(value)) = (
            key.parse::<salvo::http::HeaderName>(),
            value.parse::<salvo::http::HeaderValue>(),
        ) {
            salvo_res.headers_mut().insert(name, value);
        }
    }

    // Set body
    let body_bytes = response.body.into_bytes();
    if !body_bytes.is_empty() {
        salvo_res.write_body(body_bytes).await?;
    }

    Ok(())
}
