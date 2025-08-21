# Web Server Abstraction - Comprehensive Design Plan

## Project Overview

The `web-server-abstraction` crate provides an ergonomic abstraction layer over popular Rust web frameworks, allowing developers to write web applications once and run them on any supported framework. This addresses a major pain point in the Rust ecosystem where libraries need to implement support for multiple web frameworks separately.

## Architecture Design

### Core Abstractions

#### 1. Handler System

```rust
pub type HandlerFn = Box<dyn Fn(Request) -> BoxFuture<Result<Response>> + Send + Sync>;

pub trait Handler<T>: Clone + Send + Sync + 'static {
    fn into_handler(self) -> HandlerFn;
}
```

**Design Rationale:**

- Uses type erasure with `Box<dyn Fn>` for uniform storage
- Supports async handlers through `BoxFuture`
- Generic `Handler<T>` trait allows for different handler signatures
- Lifetime-free design avoids complex lifetime management

#### 2. Middleware System

```rust
#[async_trait]
pub trait Middleware: Send + Sync {
    async fn call(&self, req: Request, next: Next) -> Result<Response>;
}
```

**Design Rationale:**

- Inspired by Tower's middleware model
- Chain-of-responsibility pattern with `Next` continuation
- Async-native design
- Composable and reusable across frameworks

#### 3. Adapter Pattern

```rust
pub enum AdapterType {
    Mock(MockAdapter),
    #[cfg(feature = "axum")]
    Axum(AxumAdapter),
    // ... other adapters
}
```

**Design Rationale:**

- Enum-based dispatch avoids trait object complexity
- Feature flags enable conditional compilation
- Type-safe dispatch at compile time
- Easy to extend with new frameworks

### Type System Design

#### HTTP Types

```rust
pub struct Request {
    pub method: HttpMethod,
    pub uri: Uri,
    pub version: Version,
    pub headers: Headers,
    pub body: Body,
    pub extensions: HashMap<String, String>,
}

pub struct Response {
    pub status: StatusCode,
    pub headers: Headers,
    pub body: Body,
}
```

**Design Decisions:**

- Uses standard `http` crate types where possible
- Simplified extensions system (HashMap<String, String>)
- Owned data for easier movement between async boundaries
- Builder pattern for ergonomic construction

### Framework Integration Strategy

#### 1. Type Conversion Layer

Each adapter implements bidirectional type conversion:

```rust
// Framework -> Our types
fn convert_request(framework_req: FrameworkRequest) -> Result<Request>;

// Our types -> Framework
fn convert_response(our_resp: Response) -> FrameworkResponse;
```

#### 2. Routing Integration

```rust
// Map our route definitions to framework-specific routing
fn route(&mut self, path: &str, method: HttpMethod, handler: HandlerFn);
```

#### 3. Middleware Integration

```rust
// Convert our middleware to framework middleware
fn middleware(&mut self, middleware: Box<dyn Middleware>);
```

## Framework Integration Plans

### 1. Axum Integration (In Progress)

**Integration Strategy:**

```rust
impl AxumAdapter {
    fn route(&mut self, path: &str, method: HttpMethod, handler: HandlerFn) {
        let axum_handler = move |req: axum::Request| async move {
            let converted_req = convert_axum_request(req)?;
            let response = handler(converted_req).await?;
            Ok(convert_to_axum_response(response))
        };

        match method {
            HttpMethod::GET => self.router = self.router.route(path, get(axum_handler)),
            HttpMethod::POST => self.router = self.router.route(path, post(axum_handler)),
            // ... other methods
        }
    }
}
```

**Challenges:**

- Axum's extractor system integration
- Proper error handling and conversion
- State management integration
- WebSocket support

**Benefits:**

- Built on Tower (natural fit)
- Strong async support
- Growing ecosystem

### 2. Actix-Web Integration (Planned)

**Integration Strategy:**

```rust
impl ActixWebAdapter {
    fn route(&mut self, path: &str, method: HttpMethod, handler: HandlerFn) {
        let actix_handler = move |req: HttpRequest, body: web::Payload| async move {
            let converted_req = convert_actix_request(req, body).await?;
            let response = handler(converted_req).await?;
            convert_to_actix_response(response)
        };

        self.app = self.app.route(path,
            web::method(method.into()).to(actix_handler));
    }
}
```

**Challenges:**

- Actor system integration
- Different error handling model
- Extractors and guards system
- Different async runtime assumptions

**Benefits:**

- High performance
- Mature ecosystem
- Rich feature set

### 3. Rocket Integration (Planned)

**Integration Strategy:**

```rust
impl RocketAdapter {
    fn route(&mut self, path: &str, method: HttpMethod, handler: HandlerFn) {
        // Rocket's compile-time route generation requires macro magic
        // May need runtime route registration or proc-macro integration
        let rocket_handler = move |req: &rocket::Request, data: rocket::Data| async move {
            let converted_req = convert_rocket_request(req, data).await?;
            let response = handler(converted_req).await?;
            convert_to_rocket_response(response)
        };

        self.rocket = self.rocket.mount("/", routes![rocket_handler]);
    }
}
```

**Challenges:**

- Compile-time route generation vs runtime registration
- Type-safe parameter extraction
- Different async model
- Proc-macro integration needs

**Benefits:**

- Type safety
- Excellent ergonomics
- Built-in validation

### 4. Warp Integration (Planned)

**Integration Strategy:**

```rust
impl WarpAdapter {
    fn route(&mut self, path: &str, method: HttpMethod, handler: HandlerFn) {
        let filter = warp::path(path)
            .and(warp::method(method.into()))
            .and(warp::body::aggregate())
            .and_then(move |body| async move {
                let req = convert_warp_request(method, path, body)?;
                let resp = handler(req).await?;
                Ok(convert_to_warp_reply(resp))
            });

        self.routes = self.routes.or(filter);
    }
}
```

**Challenges:**

- Filter composition model
- Type-level programming complexity
- Different error handling approach
- Extractor integration

**Benefits:**

- Functional composition
- Type-safe extractors
- Excellent performance

## Middleware Ecosystem Design

### Core Middleware

#### 1. Logging Middleware

```rust
pub struct LoggingMiddleware {
    pub enabled: bool,
    pub format: LogFormat,
    pub level: LogLevel,
}
```

**Features:**

- Configurable log formats (Common Log Format, JSON, Custom)
- Request/response timing
- Error logging
- Optional request/response body logging

#### 2. CORS Middleware

```rust
pub struct CorsMiddleware {
    pub allow_origin: AllowOrigin,
    pub allow_methods: Vec<HttpMethod>,
    pub allow_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: Option<Duration>,
}
```

**Features:**

- Configurable origin policies
- Method and header whitelisting
- Credential support
- Preflight request handling

#### 3. Authentication Middleware

```rust
pub struct AuthMiddleware<T> {
    pub validator: Box<dyn AuthValidator<T>>,
    pub require_auth: bool,
    pub schemes: Vec<AuthScheme>,
}

#[async_trait]
pub trait AuthValidator<T>: Send + Sync {
    async fn validate(&self, req: &Request) -> Result<Option<T>>;
}
```

**Features:**

- Pluggable authentication validators
- Multiple auth scheme support (Bearer, Basic, Custom)
- User context injection
- Optional vs required authentication

#### 4. Rate Limiting Middleware

```rust
pub struct RateLimitMiddleware {
    pub store: Box<dyn RateLimitStore>,
    pub strategy: RateLimitStrategy,
    pub key_extractor: Box<dyn KeyExtractor>,
}
```

**Features:**

- Pluggable storage backends (in-memory, Redis, etc.)
- Multiple rate limiting algorithms (token bucket, sliding window)
- Configurable key extraction (IP, user ID, custom)
- Custom response for rate limit exceeded

### Middleware Integration Pattern

```rust
// Framework-agnostic middleware
impl Middleware for LoggingMiddleware {
    async fn call(&self, req: Request, next: Next) -> Result<Response> {
        let start = Instant::now();
        self.log_request(&req);

        let response = next.run(req).await;

        let duration = start.elapsed();
        self.log_response(&response, duration);

        response
    }
}

// Framework-specific integration
impl AxumAdapter {
    fn middleware(&mut self, middleware: Box<dyn Middleware>) -> &mut Self {
        let tower_layer = MiddlewareLayer::new(middleware);
        self.router = self.router.layer(tower_layer);
        self
    }
}
```

## Error Handling Strategy

### Error Type Hierarchy

```rust
#[derive(Error, Debug)]
pub enum WebServerError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] http::Error),

    #[error("Framework adapter error: {0}")]
    AdapterError(String),

    #[error("Custom error: {0}")]
    Custom(String),
}
```

### Error Conversion Strategy

Each adapter handles framework-specific errors:

```rust
impl From<AxumError> for WebServerError {
    fn from(err: AxumError) -> Self {
        WebServerError::AdapterError(format!("Axum error: {}", err))
    }
}
```

## Performance Considerations

### Zero-Cost Abstractions

- Static dispatch where possible
- Minimal allocations in hot paths
- Compile-time feature selection
- Efficient type conversions

### Memory Management

- Owned data structures for async boundaries
- Streaming body support
- Configurable buffer sizes
- Pool-based allocations where beneficial

### Benchmarking Strategy

```rust
// Benchmark framework overhead
#[bench]
fn bench_adapter_overhead(b: &mut Bencher) {
    // Compare direct framework usage vs abstraction layer
}

// Benchmark middleware performance
#[bench]
fn bench_middleware_chain(b: &mut Bencher) {
    // Measure middleware composition overhead
}
```

## Testing Strategy

### Unit Tests

- Individual component testing
- Mock adapter for isolated testing
- Middleware composition testing
- Error handling verification

### Integration Tests

```rust
#[tokio::test]
async fn test_framework_compatibility() {
    // Test same application on different frameworks
    let handlers = create_test_handlers();

    #[cfg(feature = "axum")]
    test_with_axum(handlers.clone()).await;

    #[cfg(feature = "actix-web")]
    test_with_actix(handlers.clone()).await;
}
```

### Property-Based Testing

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_request_response_roundtrip(
        method in any::<HttpMethod>(),
        path in "[a-zA-Z0-9/]*",
        body in any::<Vec<u8>>()
    ) {
        // Test that request/response conversion is lossless
    }
}
```

## Documentation Strategy

### API Documentation

- Comprehensive rustdoc comments
- Usage examples in every public item
- Architecture decision records
- Performance characteristics documentation

### User Guide

- Getting started tutorial
- Framework migration guide
- Middleware development guide
- Best practices documentation

### Examples

- Basic web server
- REST API example
- Middleware composition examples
- Framework comparison examples

## Roadmap and Milestones

### Version 0.1.0 ✅

- [x] Core abstraction design
- [x] Mock adapter implementation
- [x] Basic middleware system
- [x] Documentation and examples
- [x] Test infrastructure

### Version 0.2.0 (Next)

- [ ] Complete Axum adapter
- [ ] Enhanced middleware ecosystem
- [ ] Performance benchmarks
- [ ] Actix-Web adapter (basic)

### Version 0.3.0

- [ ] Rocket adapter
- [ ] Warp adapter
- [ ] Advanced routing features (params, guards)
- [ ] WebSocket support foundation

### Version 0.4.0

- [ ] Salvo adapter
- [ ] Poem adapter
- [ ] Advanced middleware (rate limiting, caching)
- [ ] Streaming support

### Version 1.0.0

- [ ] All planned framework adapters
- [ ] Production-ready performance
- [ ] Comprehensive middleware library
- [ ] Stable API guarantee

## Open Questions and Decisions

### 1. Handler Signature Flexibility

**Question:** Should we support different handler signatures like `(Request) -> Response`, `(Parts, Body) -> Response`, etc.?

**Current Decision:** Start with single signature, evaluate based on user feedback.

### 2. Streaming Support

**Question:** How to handle streaming requests/responses across different frameworks?

**Current Approach:** Start with buffered bodies, add streaming in future versions.

### 3. WebSocket Integration

**Question:** How to abstract WebSocket connections across frameworks?

**Current Plan:** Separate WebSocket abstraction trait in future version.

### 4. State Management

**Question:** How to handle framework-specific state/context injection?

**Current Approach:** Use extensions map, evaluate framework-specific solutions later.

## Contributing Guidelines

### Framework Adapter Contributions

1. Create feature-gated module in `src/adapters/`
2. Implement required methods: `bind`, `run`, `route`, `middleware`
3. Add comprehensive tests
4. Update documentation and examples
5. Add benchmark comparisons

### Middleware Contributions

1. Implement `Middleware` trait
2. Add configuration options
3. Include usage examples
4. Add performance tests
5. Document integration with different frameworks

This design provides a solid foundation for creating a truly ergonomic web server abstraction that can grow with the Rust ecosystem while maintaining performance and type safety.
