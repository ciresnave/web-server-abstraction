//! Content negotiation and advanced content handling.

use crate::core::{Middleware, Next};
use crate::types::{Request, Response};
use async_trait::async_trait;
use std::collections::HashMap;

/// Content negotiation middleware
#[derive(Debug)]
pub struct ContentNegotiationMiddleware {
    supported_types: HashMap<String, f32>, // mime type -> quality
    default_type: String,
}

impl ContentNegotiationMiddleware {
    /// Create new content negotiation middleware
    pub fn new() -> Self {
        let mut supported_types = HashMap::new();
        supported_types.insert("application/json".to_string(), 1.0);
        supported_types.insert("text/html".to_string(), 0.9);
        supported_types.insert("text/plain".to_string(), 0.8);
        supported_types.insert("application/xml".to_string(), 0.7);

        Self {
            supported_types,
            default_type: "application/json".to_string(),
        }
    }

    /// Add supported content type
    pub fn support_type(mut self, mime_type: String, quality: f32) -> Self {
        self.supported_types.insert(mime_type, quality);
        self
    }

    /// Set default content type
    pub fn default_type(mut self, mime_type: String) -> Self {
        self.default_type = mime_type;
        self
    }

    /// Parse Accept header
    fn parse_accept_header(&self, accept_header: &str) -> Vec<(String, f32)> {
        let mut types = Vec::new();

        for part in accept_header.split(',') {
            let part = part.trim();
            if let Some((mime_type, quality_str)) = part.split_once(";q=") {
                let mime_type = mime_type.trim().to_lowercase();
                let quality = quality_str.parse::<f32>().unwrap_or(1.0);
                types.push((mime_type, quality));
            } else {
                let mime_type = part.trim().to_lowercase();
                types.push((mime_type, 1.0));
            }
        }

        // Sort by quality descending
        types.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        types
    }

    /// Determine best content type
    fn negotiate_content_type(&self, accept_header: &str) -> String {
        let accepted_types = self.parse_accept_header(accept_header);

        for (accepted_type, _) in accepted_types {
            if accepted_type == "*/*" {
                return self.default_type.clone();
            }

            if self.supported_types.contains_key(&accepted_type) {
                return accepted_type;
            }

            // Handle wildcard types like "text/*"
            if accepted_type.ends_with("/*") {
                let prefix = accepted_type.trim_end_matches("/*");
                for supported_type in self.supported_types.keys() {
                    if supported_type.starts_with(prefix) {
                        return supported_type.clone();
                    }
                }
            }
        }

        self.default_type.clone()
    }
}

impl Default for ContentNegotiationMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Middleware for ContentNegotiationMiddleware {
    async fn call(&self, mut request: Request, next: Next) -> crate::Result<Response> {
        // Parse Accept header and determine best content type
        if let Some(accept_header) = request.headers.get("accept") {
            let best_type = self.negotiate_content_type(accept_header);
            request
                .extensions
                .insert("negotiated_content_type".to_string(), best_type);
        } else {
            request.extensions.insert(
                "negotiated_content_type".to_string(),
                self.default_type.clone(),
            );
        }

        let mut response = next.run(request).await?;

        // Add Vary header to indicate that response varies based on Accept header
        response
            .headers
            .insert("vary".to_string(), "accept, accept-encoding".to_string());

        Ok(response)
    }
}

/// Compression middleware
#[derive(Debug)]
pub struct CompressionMiddleware {
    enabled: bool,
    min_size: usize,
}

impl CompressionMiddleware {
    /// Create new compression middleware
    pub fn new() -> Self {
        Self {
            enabled: true,
            min_size: 1024, // Only compress responses larger than 1KB
        }
    }

    /// Set minimum size for compression
    pub fn min_size(mut self, size: usize) -> Self {
        self.min_size = size;
        self
    }

    /// Enable/disable compression
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Check if content should be compressed
    fn should_compress(&self, content_type: &str, content_length: usize) -> bool {
        if !self.enabled || content_length < self.min_size {
            return false;
        }

        // Don't compress already compressed content
        let exclude_types = [
            "image/",
            "video/",
            "audio/",
            "application/zip",
            "application/gzip",
            "application/x-rar",
            "application/pdf",
        ];

        !exclude_types
            .iter()
            .any(|&excluded| content_type.starts_with(excluded))
    }
}

impl Default for CompressionMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Middleware for CompressionMiddleware {
    async fn call(&self, request: Request, next: Next) -> crate::Result<Response> {
        let mut response = next.run(request).await?;

        if self.enabled {
            // Get content type
            let content_type = response
                .headers
                .get("content-type")
                .cloned()
                .unwrap_or_else(|| "text/plain".to_string());

            // Estimate content length (simplified)
            let content_length = 2048; // Would normally check actual body size

            if self.should_compress(&content_type, content_length) {
                // Add compression headers (simplified implementation)
                response
                    .headers
                    .insert("content-encoding".to_string(), "gzip".to_string());
                response
                    .headers
                    .insert("vary".to_string(), "accept-encoding".to_string());
            }
        }

        Ok(response)
    }
}

/// Range request handling for partial content
#[derive(Debug, Default)]
pub struct RangeMiddleware;

impl RangeMiddleware {
    pub fn new() -> Self {
        Self
    }

    /// Parse Range header
    #[allow(dead_code)]
    fn parse_range(&self, range_header: &str, content_length: usize) -> Option<(usize, usize)> {
        if !range_header.starts_with("bytes=") {
            return None;
        }

        let range_spec = range_header.strip_prefix("bytes=")?;

        if let Some((start_str, end_str)) = range_spec.split_once('-') {
            let (start, end) = if start_str.is_empty() {
                // Suffix range: -500 means last 500 bytes
                if let Ok(suffix_length) = end_str.parse::<usize>() {
                    let start = content_length.saturating_sub(suffix_length);
                    let end = content_length.saturating_sub(1);
                    (start, end)
                } else {
                    return None;
                }
            } else {
                let start = start_str.parse().ok()?;
                let end = if end_str.is_empty() {
                    // Open-ended range: 500- means from 500 to end
                    content_length.saturating_sub(1)
                } else {
                    end_str
                        .parse::<usize>()
                        .ok()?
                        .min(content_length.saturating_sub(1))
                };
                (start, end)
            };

            if start <= end && start < content_length {
                Some((start, end))
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[async_trait]
impl Middleware for RangeMiddleware {
    async fn call(&self, request: Request, next: Next) -> crate::Result<Response> {
        let mut response = next.run(request).await?;

        // Add Accept-Ranges header to indicate we support range requests
        response
            .headers
            .insert("accept-ranges".to_string(), "bytes".to_string());

        // Note: Full range request handling would require checking the Range header
        // in the request and modifying the response accordingly
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_accept_header() {
        let middleware = ContentNegotiationMiddleware::new();
        let types = middleware.parse_accept_header("text/html,application/xml;q=0.9,*/*;q=0.8");

        assert_eq!(types.len(), 3);
        assert_eq!(types[0], ("text/html".to_string(), 1.0));
        assert_eq!(types[1], ("application/xml".to_string(), 0.9));
        assert_eq!(types[2], ("*/*".to_string(), 0.8));
    }

    #[test]
    fn test_content_type_negotiation() {
        let middleware = ContentNegotiationMiddleware::new();

        let result = middleware.negotiate_content_type("application/json,text/html;q=0.9");
        assert_eq!(result, "application/json");

        let result = middleware.negotiate_content_type("text/html,application/json;q=0.9");
        assert_eq!(result, "text/html");

        let result = middleware.negotiate_content_type("*/*");
        assert_eq!(result, "application/json"); // default
    }

    #[test]
    fn test_compression_should_compress() {
        let middleware = CompressionMiddleware::new();

        assert!(middleware.should_compress("text/html", 2048));
        assert!(!middleware.should_compress("text/html", 512)); // too small
        assert!(!middleware.should_compress("image/jpeg", 2048)); // excluded type
    }

    #[test]
    fn test_range_parsing() {
        let middleware = RangeMiddleware::new();

        assert_eq!(middleware.parse_range("bytes=0-499", 1000), Some((0, 499)));
        assert_eq!(middleware.parse_range("bytes=500-", 1000), Some((500, 999)));
        assert_eq!(middleware.parse_range("bytes=-500", 1000), Some((500, 999)));
        assert_eq!(middleware.parse_range("bytes=invalid", 1000), None);
    }
}
