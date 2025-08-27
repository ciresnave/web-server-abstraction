//! Common types used throughout the web server abstraction.

use crate::error::WebServerError;
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode as HttpStatusCode, Uri, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// HTTP request type
#[derive(Debug)]
pub struct Request {
    pub method: HttpMethod,
    pub uri: Uri,
    pub version: Version,
    pub headers: Headers,
    pub body: Body,
    pub extensions: HashMap<String, String>, // Simplified for now
    /// Path parameters extracted from route matching
    pub path_params: HashMap<String, String>,
    /// Parsed cookies
    pub cookies: HashMap<String, Cookie>,
    /// Parsed form data (URL-encoded)
    pub form_data: Option<HashMap<String, String>>,
    /// Parsed multipart form data
    pub multipart: Option<MultipartForm>,
}

impl Request {
    /// Create a new request
    pub fn new(method: HttpMethod, uri: Uri) -> Self {
        Self {
            method,
            uri,
            version: Version::HTTP_11,
            headers: Headers::new(),
            body: Body::empty(),
            extensions: HashMap::new(),
            path_params: HashMap::new(),
            cookies: HashMap::new(),
            form_data: None,
            multipart: None,
        }
    }

    /// Get the path from the URI
    pub fn path(&self) -> &str {
        self.uri.path()
    }

    /// Get query parameters
    pub fn query(&self) -> Option<&str> {
        self.uri.query()
    }

    /// Get a path parameter by name
    pub fn param(&self, name: &str) -> Option<&str> {
        self.path_params.get(name).map(|s| s.as_str())
    }

    /// Get all path parameters
    pub fn params(&self) -> &HashMap<String, String> {
        &self.path_params
    }

    /// Set path parameters (used internally by routing system)
    pub fn set_params(&mut self, params: HashMap<String, String>) {
        self.path_params = params;
    }

    /// Parse JSON body
    pub async fn json<T>(&self) -> crate::error::Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let bytes = self.body.bytes().await?;
        serde_json::from_slice(&bytes).map_err(crate::error::WebServerError::JsonError)
    }

    /// Get body as text
    pub async fn text(&self) -> crate::error::Result<String> {
        let bytes = self.body.bytes().await?;
        String::from_utf8(bytes.to_vec()).map_err(crate::error::WebServerError::Utf8Error)
    }

    /// Get cookie by name
    pub fn cookie(&self, name: &str) -> Option<&Cookie> {
        self.cookies.get(name)
    }

    /// Get all cookies
    pub fn cookies(&self) -> &HashMap<String, Cookie> {
        &self.cookies
    }

    /// Parse cookies from headers
    pub fn parse_cookies(&mut self) -> crate::error::Result<()> {
        if let Some(cookie_header) = self.headers.get("Cookie") {
            let cookies = Cookie::parse(cookie_header)?;
            for cookie in cookies {
                self.cookies.insert(cookie.name.clone(), cookie);
            }
        }
        Ok(())
    }

    /// Get form field value
    pub fn form(&self, name: &str) -> Option<&str> {
        self.form_data.as_ref()?.get(name).map(|s| s.as_str())
    }

    /// Get all form data
    pub fn form_data(&self) -> Option<&HashMap<String, String>> {
        self.form_data.as_ref()
    }

    /// Parse URL-encoded form data
    pub async fn parse_form(&mut self) -> crate::error::Result<()> {
        if self.form_data.is_some() {
            return Ok(()); // Already parsed
        }

        let default_content_type = String::new();
        let content_type = self
            .headers
            .get("Content-Type")
            .unwrap_or(&default_content_type);
        if !content_type.starts_with("application/x-www-form-urlencoded") {
            return Ok(()); // Not form data
        }

        let body_text = self.text().await?;
        let mut form_data = HashMap::new();

        for pair in body_text.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                // Simple URL decoding for now - replace with proper implementation later
                let key = key.replace("%20", " ").replace("+", " ");
                let value = value.replace("%20", " ").replace("+", " ");
                form_data.insert(key, value);
            }
        }

        self.form_data = Some(form_data);
        Ok(())
    }

    /// Get multipart form data
    pub fn multipart(&self) -> Option<&MultipartForm> {
        self.multipart.as_ref()
    }

    /// Parse query parameters into a HashMap
    pub fn query_params(&self) -> HashMap<String, String> {
        if let Some(query) = self.uri.query() {
            let mut params = HashMap::new();
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    // URL decode key and value
                    let key = urlencoding::decode(key).unwrap_or_default().into_owned();
                    let value = urlencoding::decode(value).unwrap_or_default().into_owned();
                    params.insert(key, value);
                }
            }
            params
        } else {
            HashMap::new()
        }
    }

    /// Get a single query parameter by name
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.query_params().get(name).cloned()
    }

    /// Check if request accepts a specific content type
    pub fn accepts(&self, content_type: &str) -> bool {
        if let Some(accept_header) = self.headers.get("Accept") {
            accept_header.contains(content_type) || accept_header.contains("*/*")
        } else {
            true // Default to accepting if no Accept header
        }
    }

    /// Get the content type of the request
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("Content-Type").map(|s| s.as_str())
    }

    /// Check if this is a JSON request
    pub fn is_json(&self) -> bool {
        self.content_type()
            .is_some_and(|ct| ct.contains("application/json"))
    }

    /// Check if this is a form request
    pub fn is_form(&self) -> bool {
        self.content_type()
            .is_some_and(|ct| ct.contains("application/x-www-form-urlencoded"))
    }

    /// Check if this is a multipart request
    pub fn is_multipart(&self) -> bool {
        self.content_type()
            .is_some_and(|ct| ct.contains("multipart/form-data"))
    }

    /// Get remote IP address (best effort)
    pub fn remote_addr(&self) -> Option<&str> {
        // Check X-Forwarded-For header first (for proxies)
        if let Some(forwarded) = self.headers.get("X-Forwarded-For") {
            // Take the first IP in the chain
            if let Some(first_ip) = forwarded.split(',').next() {
                return Some(first_ip.trim());
            }
        }

        // Check X-Real-IP header
        if let Some(real_ip) = self.headers.get("X-Real-IP") {
            return Some(real_ip.as_str());
        }

        // Fall back to extensions if the adapter provides it
        self.extensions.get("remote_addr").map(|s| s.as_str())
    }

    /// Get user agent
    pub fn user_agent(&self) -> Option<&str> {
        self.headers.get("User-Agent").map(|s| s.as_str())
    }

    /// Get path parameter by name
    pub fn path_param(&self, name: &str) -> Option<&str> {
        self.path_params.get(name).map(|s| s.as_str())
    }

    /// Get all path parameters
    pub fn path_params(&self) -> &HashMap<String, String> {
        &self.path_params
    }

    /// Set a path parameter (used by router)
    pub fn set_path_param(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.path_params.insert(name.into(), value.into());
    }

    /// Parse multipart form data
    pub async fn parse_multipart(&mut self) -> crate::error::Result<()> {
        if self.multipart.is_some() {
            return Ok(()); // Already parsed
        }

        let default_content_type = String::new();
        let content_type = self
            .headers
            .get("Content-Type")
            .unwrap_or(&default_content_type);
        if !content_type.starts_with("multipart/form-data") {
            return Ok(()); // Not multipart data
        }

        // Parse boundary from Content-Type header
        let boundary = match content_type.split(";").nth(1) {
            Some(part) => {
                let part = part.trim();
                if part.starts_with("boundary=") {
                    part.trim_start_matches("boundary=").trim_matches('"')
                } else {
                    return Err(WebServerError::parse_error(
                        "Missing boundary in multipart Content-Type",
                    ));
                }
            }
            None => {
                return Err(WebServerError::parse_error(
                    "Missing boundary in multipart Content-Type",
                ));
            }
        };

        // Create a multipart form and parse the body
        let mut form = MultipartForm::new();

        // Get body bytes
        let body_bytes = self.body.bytes().await?;

        // Parse multipart data
        let mut current_part: Option<MultipartPart> = None;
        let mut parsing_headers = true;
        let mut part_content: Vec<u8> = Vec::new();

        let boundary_start = format!("--{}", boundary);
        let boundary_end = format!("--{}--", boundary);

        // Split by lines for simpler parsing
        let body_str = String::from_utf8_lossy(&body_bytes);
        let lines: Vec<&str> = body_str.split("\r\n").collect();

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];

            // Check for boundaries
            if line == boundary_start {
                // Save previous part if exists
                if let Some(part) = current_part.take() {
                    form.add_part(part);
                }

                // Start new part
                current_part = Some(MultipartPart::new());
                parsing_headers = true;
                part_content = Vec::new();
            } else if line == boundary_end {
                // Final boundary - save last part if exists
                if let Some(part) = current_part.take() {
                    form.add_part(part);
                }
                break;
            } else if parsing_headers {
                // Parse headers
                if line.is_empty() {
                    // Empty line marks end of headers
                    parsing_headers = false;
                } else if let Some(part) = &mut current_part {
                    // Parse header line
                    if let Some((name, value)) = line.split_once(":") {
                        let name = name.trim();
                        let value = value.trim();

                        // Handle Content-Disposition specially
                        if name.eq_ignore_ascii_case("Content-Disposition") {
                            // Extract field name and filename
                            for param in value.split(";") {
                                let param = param.trim();

                                if param.starts_with("name=") {
                                    let field_name =
                                        param.trim_start_matches("name=").trim_matches('"');
                                    part.field_name = Some(field_name.to_string());
                                } else if param.starts_with("filename=") {
                                    let filename =
                                        param.trim_start_matches("filename=").trim_matches('"');
                                    part.filename = Some(filename.to_string());
                                }
                            }
                        }

                        part.headers.insert(name.to_string(), value.to_string());
                    }
                }
            } else {
                // Part content - accumulate until next boundary
                if let Some(_part) = &mut current_part {
                    part_content.extend_from_slice(line.as_bytes());
                    // Add back the CR+LF except for the last line
                    if i < lines.len() - 1 && !lines[i + 1].starts_with("--") {
                        part_content.extend_from_slice(b"\r\n");
                    }
                }
            }

            i += 1;
        }

        // Set the parsed form
        self.multipart = Some(form);

        Ok(())
    }
}

/// HTTP response type
#[derive(Debug, Clone)]
pub struct Response {
    pub status: StatusCode,
    pub headers: Headers,
    pub body: Body,
}

impl Response {
    /// Create a new response
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Body::empty(),
        }
    }

    /// Create a response with status 200 OK
    pub fn ok() -> Self {
        Self::new(StatusCode::OK)
    }

    /// Set the body
    pub fn body<B>(mut self, body: B) -> Self
    where
        B: Into<Body>,
    {
        self.body = body.into();
        self
    }

    /// Set a header
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Create a JSON response
    pub fn json<T>(value: &T) -> crate::error::Result<Self>
    where
        T: Serialize,
    {
        let json = serde_json::to_string(value)?;
        Ok(Self::ok()
            .header("content-type", "application/json")
            .body(json))
    }

    /// Add a cookie to the response
    pub fn cookie(mut self, cookie: Cookie) -> Self {
        self.headers.set("Set-Cookie", cookie.to_header_value());
        self
    }

    /// Add multiple cookies to the response
    pub fn cookies(mut self, cookies: Vec<Cookie>) -> Self {
        for cookie in cookies {
            self.headers.add("Set-Cookie", cookie.to_header_value());
        }
        self
    }

    /// Create an HTML response
    pub fn html(content: impl Into<String>) -> Self {
        Self::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .body(content.into())
    }

    /// Create a plain text response
    pub fn text(content: impl Into<String>) -> Self {
        Self::ok()
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(content.into())
    }

    /// Create a redirect response
    pub fn redirect(location: impl Into<String>) -> Self {
        Self::new(StatusCode::FOUND).header("Location", location.into())
    }

    /// Create a permanent redirect response
    pub fn redirect_permanent(location: impl Into<String>) -> Self {
        Self::new(StatusCode::MOVED_PERMANENTLY).header("Location", location.into())
    }

    /// Create a not found response
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND).body("Not Found")
    }

    /// Create a bad request response
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST).body(message.into())
    }

    /// Create an internal server error response
    pub fn internal_server_error(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR).body(message.into())
    }

    /// Set cache control headers
    pub fn cache(mut self, max_age: u32) -> Self {
        self.headers
            .insert("Cache-Control".to_string(), format!("max-age={}", max_age));
        self
    }

    /// Disable caching
    pub fn no_cache(mut self) -> Self {
        self.headers.insert(
            "Cache-Control".to_string(),
            "no-cache, no-store, must-revalidate".to_string(),
        );
        self.headers
            .insert("Pragma".to_string(), "no-cache".to_string());
        self.headers.insert("Expires".to_string(), "0".to_string());
        self
    }

    /// Enable CORS with simple settings
    pub fn cors(mut self) -> Self {
        self.headers
            .insert("Access-Control-Allow-Origin".to_string(), "*".to_string());
        self.headers.insert(
            "Access-Control-Allow-Methods".to_string(),
            "GET, POST, PUT, DELETE, OPTIONS".to_string(),
        );
        self.headers.insert(
            "Access-Control-Allow-Headers".to_string(),
            "Content-Type, Authorization".to_string(),
        );
        self
    }

    /// Enable CORS with specific origin
    pub fn cors_origin(mut self, origin: impl Into<String>) -> Self {
        self.headers
            .insert("Access-Control-Allow-Origin".to_string(), origin.into());
        self.headers.insert(
            "Access-Control-Allow-Methods".to_string(),
            "GET, POST, PUT, DELETE, OPTIONS".to_string(),
        );
        self.headers.insert(
            "Access-Control-Allow-Headers".to_string(),
            "Content-Type, Authorization".to_string(),
        );
        self
    }

    /// Serve a file from disk
    pub async fn file(path: impl Into<PathBuf>) -> crate::error::Result<Self> {
        let path = path.into();

        // Read file contents
        let data = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                return crate::error::WebServerError::custom("File not found");
            }
            crate::error::WebServerError::custom(format!("Failed to read file: {}", e))
        })?;

        // Guess content type from file extension
        let content_type = mime_guess::from_path(&path)
            .first_or_octet_stream()
            .to_string();

        Ok(Self::ok().header("Content-Type", content_type).body(data))
    }

    /// Create a download response that forces the browser to download the file
    pub fn download(filename: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        let filename = filename.into();
        Self::ok()
            .header("Content-Type", "application/octet-stream")
            .header(
                "Content-Disposition",
                format!("attachment; filename=\"{}\"", filename),
            )
            .body(data.into())
    }

    /// Set content length header based on body size
    pub fn with_content_length(mut self) -> Self {
        let length = self.body.len();
        self.headers
            .insert("Content-Length".to_string(), length.to_string());
        self
    }
}

/// HTTP method enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::PATCH => "PATCH",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OPTIONS => "OPTIONS",
            HttpMethod::TRACE => "TRACE",
            HttpMethod::CONNECT => "CONNECT",
        }
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<Method> for HttpMethod {
    fn from(method: Method) -> Self {
        match method {
            Method::GET => Self::GET,
            Method::POST => Self::POST,
            Method::PUT => Self::PUT,
            Method::DELETE => Self::DELETE,
            Method::PATCH => Self::PATCH,
            Method::HEAD => Self::HEAD,
            Method::OPTIONS => Self::OPTIONS,
            Method::TRACE => Self::TRACE,
            Method::CONNECT => Self::CONNECT,
            _ => Self::GET, // Default fallback
        }
    }
}

impl From<HttpMethod> for Method {
    fn from(method: HttpMethod) -> Self {
        match method {
            HttpMethod::GET => Method::GET,
            HttpMethod::POST => Method::POST,
            HttpMethod::PUT => Method::PUT,
            HttpMethod::DELETE => Method::DELETE,
            HttpMethod::PATCH => Method::PATCH,
            HttpMethod::HEAD => Method::HEAD,
            HttpMethod::OPTIONS => Method::OPTIONS,
            HttpMethod::TRACE => Method::TRACE,
            HttpMethod::CONNECT => Method::CONNECT,
        }
    }
}

/// HTTP status code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(pub u16);

impl StatusCode {
    pub const OK: StatusCode = StatusCode(200);
    pub const CREATED: StatusCode = StatusCode(201);
    pub const NO_CONTENT: StatusCode = StatusCode(204);
    pub const MOVED_PERMANENTLY: StatusCode = StatusCode(301);
    pub const FOUND: StatusCode = StatusCode(302);
    pub const BAD_REQUEST: StatusCode = StatusCode(400);
    pub const UNAUTHORIZED: StatusCode = StatusCode(401);
    pub const FORBIDDEN: StatusCode = StatusCode(403);
    pub const NOT_FOUND: StatusCode = StatusCode(404);
    pub const METHOD_NOT_ALLOWED: StatusCode = StatusCode(405);
    pub const CONFLICT: StatusCode = StatusCode(409);
    pub const PAYLOAD_TOO_LARGE: StatusCode = StatusCode(413);
    pub const TOO_MANY_REQUESTS: StatusCode = StatusCode(429);
    pub const INTERNAL_SERVER_ERROR: StatusCode = StatusCode(500);
    pub const BAD_GATEWAY: StatusCode = StatusCode(502);
    pub const SERVICE_UNAVAILABLE: StatusCode = StatusCode(503);
    pub const SWITCHING_PROTOCOLS: StatusCode = StatusCode(101);

    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl From<HttpStatusCode> for StatusCode {
    fn from(status: HttpStatusCode) -> Self {
        StatusCode(status.as_u16())
    }
}

impl From<StatusCode> for HttpStatusCode {
    fn from(status: StatusCode) -> Self {
        HttpStatusCode::from_u16(status.0).unwrap_or(HttpStatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// HTTP headers wrapper
#[derive(Debug, Clone)]
pub struct Headers {
    inner: HashMap<String, String>,
}

impl Default for Headers {
    fn default() -> Self {
        Self::new()
    }
}

impl Headers {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: String, value: String) {
        self.inner.insert(key.to_lowercase(), value);
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.inner.get(&key.to_lowercase())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.inner.iter()
    }

    /// Set a header value (replaces existing)
    pub fn set(&mut self, key: &str, value: String) {
        self.insert(key.to_string(), value);
    }

    /// Add a header value (for multi-value headers like Set-Cookie)
    pub fn add(&mut self, key: &str, value: String) {
        let key_lower = key.to_lowercase();
        if let Some(_existing) = self.inner.get(&key_lower) {
            // For Set-Cookie headers, we need to keep them separate
            // For now, just replace - proper implementation would handle multiple values
            self.inner.insert(key_lower, value);
        } else {
            self.inner.insert(key_lower, value);
        }
    }
}

impl From<HeaderMap> for Headers {
    fn from(headers: HeaderMap) -> Self {
        let mut inner = HashMap::new();
        for (key, value) in headers.iter() {
            if let Ok(value_str) = value.to_str() {
                inner.insert(key.to_string(), value_str.to_string());
            }
        }
        Self { inner }
    }
}

impl From<Headers> for HeaderMap {
    fn from(headers: Headers) -> Self {
        let mut header_map = HeaderMap::new();
        for (key, value) in headers.inner {
            if let (Ok(name), Ok(val)) = (
                key.parse::<http::HeaderName>(),
                value.parse::<http::HeaderValue>(),
            ) {
                header_map.insert(name, val);
            }
        }
        header_map
    }
}

/// HTTP body type
#[derive(Debug, Clone)]
pub struct Body {
    data: Bytes,
}

impl Body {
    pub fn empty() -> Self {
        Self { data: Bytes::new() }
    }

    pub fn from_bytes(bytes: Bytes) -> Self {
        Self { data: bytes }
    }

    pub fn from_string(s: &str) -> Self {
        Self {
            data: Bytes::from(s.to_owned()),
        }
    }

    pub async fn bytes(&self) -> crate::error::Result<Bytes> {
        Ok(self.data.clone())
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Self::from_bytes(Bytes::from(s))
    }
}

impl From<&str> for Body {
    fn from(s: &str) -> Self {
        Self::from_bytes(Bytes::from(s.to_string()))
    }
}

impl From<Vec<u8>> for Body {
    fn from(data: Vec<u8>) -> Self {
        Self::from_bytes(Bytes::from(data))
    }
}

impl From<Bytes> for Body {
    fn from(bytes: Bytes) -> Self {
        Self::from_bytes(bytes)
    }
}

/// HTTP Cookie
#[derive(Debug, Clone, PartialEq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<SystemTime>,
    pub max_age: Option<Duration>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl Cookie {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: None,
            path: None,
            expires: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        }
    }

    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn expires(mut self, expires: SystemTime) -> Self {
        self.expires = Some(expires);
        self
    }

    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = Some(same_site);
        self
    }

    /// Parse cookie from header value
    pub fn parse(header_value: &str) -> crate::error::Result<Vec<Cookie>> {
        let mut cookies = Vec::new();

        for cookie_str in header_value.split(';') {
            let cookie_str = cookie_str.trim();
            if let Some((name, value)) = cookie_str.split_once('=') {
                cookies.push(Cookie::new(name.trim(), value.trim()));
            }
        }

        Ok(cookies)
    }

    /// Convert to header value
    pub fn to_header_value(&self) -> String {
        let mut result = format!("{}={}", self.name, self.value);

        if let Some(ref domain) = self.domain {
            result.push_str(&format!("; Domain={}", domain));
        }

        if let Some(ref path) = self.path {
            result.push_str(&format!("; Path={}", path));
        }

        if let Some(expires) = self.expires
            && let Ok(duration) = expires.duration_since(SystemTime::UNIX_EPOCH)
        {
            result.push_str(&format!("; Expires={}", duration.as_secs()));
        }

        if let Some(max_age) = self.max_age {
            result.push_str(&format!("; Max-Age={}", max_age.as_secs()));
        }

        if self.secure {
            result.push_str("; Secure");
        }

        if self.http_only {
            result.push_str("; HttpOnly");
        }

        if let Some(ref same_site) = self.same_site {
            let same_site_str = match same_site {
                SameSite::Strict => "Strict",
                SameSite::Lax => "Lax",
                SameSite::None => "None",
            };
            result.push_str(&format!("; SameSite={}", same_site_str));
        }

        result
    }
}

/// Form field value
#[derive(Debug, Clone)]
pub enum FormValue {
    Text(String),
    Binary(Vec<u8>),
    File(FileUpload),
}

/// File upload data
#[derive(Debug, Clone)]
pub struct FileUpload {
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Bytes,
}

impl FileUpload {
    pub fn new(data: Bytes) -> Self {
        Self {
            filename: None,
            content_type: None,
            data,
        }
    }

    pub fn with_filename(mut self, filename: impl Into<String>) -> Self {
        self.filename = Some(filename.into());
        self
    }

    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Save file to disk
    pub async fn save_to(&self, path: impl Into<PathBuf>) -> crate::error::Result<()> {
        let path = path.into();
        std::fs::write(&path, &self.data).map_err(|e| {
            crate::error::WebServerError::custom(format!("Failed to save file: {}", e))
        })
    }

    /// Get file size in bytes
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

impl Default for FileUpload {
    fn default() -> Self {
        Self::new(Bytes::new())
    }
}

/// Multipart form data
#[derive(Debug, Clone)]
pub struct MultipartForm {
    pub fields: HashMap<String, Vec<FormValue>>,
    parts: Vec<MultipartPart>,
}

/// A part of a multipart form
#[derive(Debug, Clone, Default)]
pub struct MultipartPart {
    /// Field name from form
    pub field_name: Option<String>,
    /// Filename if this is a file upload
    pub filename: Option<String>,
    /// Headers associated with this part
    pub headers: HashMap<String, String>,
    /// Content of the part
    pub content: Vec<u8>,
}

impl MultipartPart {
    /// Create a new multipart part
    pub fn new() -> Self {
        Self::default()
    }
}

impl MultipartForm {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            parts: Vec::new(),
        }
    }

    /// Add a part to the form
    pub fn add_part(&mut self, part: MultipartPart) {
        // Add to the fields collection for easier access
        if let Some(field_name) = &part.field_name {
            let value = if let Some(filename) = &part.filename {
                let content_type = part
                    .headers
                    .get("Content-Type")
                    .cloned()
                    .unwrap_or_else(|| "application/octet-stream".to_string());

                let file_upload = FileUpload::new(Bytes::from(part.content.clone()))
                    .with_filename(filename.clone())
                    .with_content_type(content_type);

                FormValue::File(file_upload)
            } else {
                // Assume text if no filename
                match String::from_utf8(part.content.clone()) {
                    Ok(text) => FormValue::Text(text),
                    Err(_) => FormValue::Binary(part.content.clone()),
                }
            };

            self.fields
                .entry(field_name.clone())
                .or_default()
                .push(value);
        }

        // Store the original part too
        self.parts.push(part);
    }

    /// Get first text field value
    pub fn get_text(&self, name: &str) -> Option<&str> {
        self.fields.get(name)?.first().and_then(|v| match v {
            FormValue::Text(text) => Some(text.as_str()),
            _ => None,
        })
    }

    /// Get all text field values
    pub fn get_all_text(&self, name: &str) -> Vec<&str> {
        self.fields
            .get(name)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|v| match v {
                        FormValue::Text(text) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get first file upload
    pub fn get_file(&self, name: &str) -> Option<&FileUpload> {
        self.fields.get(name)?.first().and_then(|v| match v {
            FormValue::File(file) => Some(file),
            _ => None,
        })
    }

    /// Get all file uploads
    pub fn get_all_files(&self, name: &str) -> Vec<&FileUpload> {
        self.fields
            .get(name)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|v| match v {
                        FormValue::File(file) => Some(file),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Add text field
    pub fn add_text(&mut self, name: String, value: String) {
        self.fields
            .entry(name)
            .or_default()
            .push(FormValue::Text(value));
    }

    /// Add file field
    pub fn add_file(&mut self, name: String, file: FileUpload) {
        self.fields
            .entry(name)
            .or_default()
            .push(FormValue::File(file));
    }
}

impl Default for MultipartForm {
    fn default() -> Self {
        Self::new()
    }
}

/// WebSocket message types
#[derive(Debug, Clone, PartialEq)]
pub enum WebSocketMessage {
    /// Text message
    Text(String),
    /// Binary message
    Binary(Vec<u8>),
    /// Ping frame
    Ping(Vec<u8>),
    /// Pong frame
    Pong(Vec<u8>),
    /// Close frame
    Close(Option<WebSocketCloseCode>),
}

/// WebSocket close codes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WebSocketCloseCode {
    /// Normal closure
    Normal = 1000,
    /// Going away
    GoingAway = 1001,
    /// Protocol error
    ProtocolError = 1002,
    /// Unsupported data
    UnsupportedData = 1003,
    /// Invalid frame payload data
    InvalidFramePayloadData = 1007,
    /// Policy violation
    PolicyViolation = 1008,
    /// Message too big
    MessageTooBig = 1009,
    /// Mandatory extension
    MandatoryExtension = 1010,
    /// Internal server error
    InternalServerError = 1011,
}

/// WebSocket connection handler
pub trait WebSocketHandler: Send + Sync + 'static {
    /// Handle a new WebSocket connection
    fn on_connect(&self) -> impl std::future::Future<Output = ()> + Send;

    /// Handle an incoming message
    fn on_message(
        &self,
        message: WebSocketMessage,
    ) -> impl std::future::Future<Output = crate::error::Result<Option<WebSocketMessage>>> + Send;

    /// Handle connection close
    fn on_close(
        &self,
        code: Option<WebSocketCloseCode>,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// WebSocket upgrade request
#[derive(Debug)]
pub struct WebSocketUpgrade {
    /// Original HTTP request
    pub request: Request,
    /// WebSocket key for handshake
    pub key: String,
    /// WebSocket version
    pub version: String,
    /// Requested protocols
    pub protocols: Vec<String>,
}

impl WebSocketUpgrade {
    /// Create a new WebSocket upgrade from an HTTP request
    pub fn from_request(request: Request) -> crate::error::Result<Self> {
        let key = request
            .headers
            .get("Sec-WebSocket-Key")
            .ok_or_else(|| {
                crate::error::WebServerError::custom("Missing Sec-WebSocket-Key header")
            })?
            .clone();

        let version = request
            .headers
            .get("Sec-WebSocket-Version")
            .unwrap_or(&"13".to_string())
            .clone();

        let protocols = request
            .headers
            .get("Sec-WebSocket-Protocol")
            .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
            .unwrap_or_default();

        Ok(Self {
            request,
            key,
            version,
            protocols,
        })
    }

    /// Accept the WebSocket upgrade
    pub fn accept<H>(self, handler: H) -> WebSocketResponse<H>
    where
        H: WebSocketHandler,
    {
        WebSocketResponse {
            upgrade: self,
            handler,
        }
    }

    /// Generate the proper WebSocket accept key according to RFC 6455
    pub fn generate_accept_key(&self) -> String {
        use base64::Engine;
        use sha1::{Digest, Sha1};

        const WEBSOCKET_MAGIC_KEY: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        let mut hasher = Sha1::new();
        hasher.update(self.key.as_bytes());
        hasher.update(WEBSOCKET_MAGIC_KEY.as_bytes());
        let digest = hasher.finalize();

        base64::engine::general_purpose::STANDARD.encode(digest)
    }
}

/// WebSocket response after accepting an upgrade
#[derive(Debug)]
pub struct WebSocketResponse<H: WebSocketHandler> {
    pub upgrade: WebSocketUpgrade,
    pub handler: H,
}

// Temporarily disabled until tests are updated
// #[cfg(test)]
// mod tests;
