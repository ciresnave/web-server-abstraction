//! Static file serving middleware and utilities.

use crate::core::Handler;
use crate::error::WebServerError;
use crate::types::{Request, Response, StatusCode};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Static file serving configuration
#[derive(Debug, Clone)]
pub struct StaticFileConfig {
    /// Root directory for static files
    pub root_dir: PathBuf,
    /// URL prefix for static files (e.g., "/static")
    pub url_prefix: String,
    /// Enable directory listing
    pub show_index: bool,
    /// Default index files to serve
    pub index_files: Vec<String>,
    /// Enable content compression
    pub compress: bool,
    /// Enable caching headers
    pub cache: bool,
    /// Cache max-age in seconds
    pub cache_max_age: u32,
}

impl Default for StaticFileConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from("./static"),
            url_prefix: "/static".to_string(),
            show_index: false,
            index_files: vec!["index.html".to_string(), "index.htm".to_string()],
            compress: true,
            cache: true,
            cache_max_age: 3600, // 1 hour
        }
    }
}

/// Static file handler
#[derive(Debug, Clone, Default)]
pub struct StaticFileHandler {
    config: StaticFileConfig,
}

impl StaticFileHandler {
    /// Create a new static file handler
    pub fn new(config: StaticFileConfig) -> Self {
        Self { config }
    }

    /// Set root directory
    pub fn root_dir(mut self, root_dir: impl Into<PathBuf>) -> Self {
        self.config.root_dir = root_dir.into();
        self
    }

    /// Set URL prefix
    pub fn url_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config.url_prefix = prefix.into();
        self
    }

    /// Enable/disable directory listing
    pub fn show_index(mut self, show: bool) -> Self {
        self.config.show_index = show;
        self
    }

    /// Enable/disable caching
    pub fn cache(mut self, cache: bool) -> Self {
        self.config.cache = cache;
        self
    }

    /// Set cache max-age
    pub fn cache_max_age(mut self, max_age: u32) -> Self {
        self.config.cache_max_age = max_age;
        self
    }

    /// Serve a static file
    async fn serve_file(&self, file_path: &Path) -> Result<Response, WebServerError> {
        // Check if file exists and is readable
        if !file_path.exists() {
            return Ok(Response::new(StatusCode::NOT_FOUND).body("File not found"));
        }

        if !file_path.is_file() {
            return Ok(Response::new(StatusCode::FORBIDDEN).body("Not a file"));
        }

        // Read file content
        let content = tokio::fs::read(file_path)
            .await
            .map_err(|e| WebServerError::custom(format!("Failed to read file: {}", e)))?;

        let mut response = Response::ok().body(content);

        // Set content type based on file extension
        if let Some(content_type) = mime_type_for_file(file_path) {
            response = response.header("Content-Type", content_type);
        }

        // Set cache headers
        if self.config.cache {
            response = response
                .header(
                    "Cache-Control",
                    format!("public, max-age={}", self.config.cache_max_age),
                )
                .header("ETag", generate_etag(file_path).await?);
        }

        Ok(response)
    }

    /// Serve directory index
    async fn serve_directory(
        &self,
        dir_path: &Path,
        url_path: &str,
    ) -> Result<Response, WebServerError> {
        if !self.config.show_index {
            return Ok(Response::new(StatusCode::FORBIDDEN).body("Directory listing disabled"));
        }

        // Try to find index files first
        for index_file in &self.config.index_files {
            let index_path = dir_path.join(index_file);
            if index_path.is_file() {
                return self.serve_file(&index_path).await;
            }
        }

        // Generate directory listing
        let entries = tokio::fs::read_dir(dir_path)
            .await
            .map_err(|e| WebServerError::custom(format!("Failed to read directory: {}", e)))?;

        let mut html = String::new();
        html.push_str(&format!(
            "<html><head><title>Index of {}</title></head><body>",
            url_path
        ));
        html.push_str(&format!("<h1>Index of {}</h1><hr><pre>", url_path));

        // Add parent directory link if not root
        if url_path != "/" {
            let parent_path = Path::new(url_path)
                .parent()
                .and_then(|p| p.to_str())
                .unwrap_or("/");
            html.push_str(&format!("<a href=\"{}\">../</a>\n", parent_path));
        }

        // Read directory entries
        let mut entries_vec = Vec::new();
        let mut entries_stream = entries;
        while let Some(entry) = entries_stream
            .next_entry()
            .await
            .map_err(|e| WebServerError::custom(format!("Failed to read directory entry: {}", e)))?
        {
            entries_vec.push(entry);
        }

        // Sort entries
        entries_vec.sort_by_key(|a| a.file_name());

        // Add directory entries
        for entry in entries_vec {
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            let metadata = entry
                .metadata()
                .await
                .map_err(|e| WebServerError::custom(format!("Failed to read metadata: {}", e)))?;

            let url_name = if metadata.is_dir() {
                format!("{}/", file_name_str)
            } else {
                file_name_str.to_string()
            };

            let full_url = if url_path.ends_with('/') {
                format!("{}{}", url_path, url_name)
            } else {
                format!("{}/{}", url_path, url_name)
            };

            html.push_str(&format!("<a href=\"{}\">{}</a>\n", full_url, url_name));
        }

        html.push_str("</pre><hr></body></html>");

        Ok(Response::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .body(html))
    }
}

impl StaticFileHandler {
    /// Handle a static file request
    pub async fn handle(&self, request: Request) -> Result<Response, WebServerError> {
        let url_path = request.uri.path();

        // Check if URL starts with our prefix
        if !url_path.starts_with(&self.config.url_prefix) {
            return Ok(Response::new(StatusCode::NOT_FOUND).body("Not found"));
        }

        // Remove prefix to get relative path
        let relative_path = url_path
            .strip_prefix(&self.config.url_prefix)
            .unwrap_or(url_path)
            .trim_start_matches('/');

        // Construct full file path
        let file_path = self.config.root_dir.join(relative_path);

        // Security check - ensure path is within root directory
        if !file_path.starts_with(&self.config.root_dir) {
            return Ok(Response::new(StatusCode::FORBIDDEN).body("Access denied"));
        }

        if file_path.is_file() {
            self.serve_file(&file_path).await
        } else if file_path.is_dir() {
            self.serve_directory(&file_path, url_path).await
        } else {
            Ok(Response::new(StatusCode::NOT_FOUND).body("File not found"))
        }
    }
}

/// Create a function-based handler for static files
impl Handler<()> for StaticFileHandler {
    fn into_handler(self) -> crate::core::HandlerFn {
        Box::new(move |req| {
            let handler = self.clone();
            Box::pin(async move { handler.handle(req).await })
        })
    }
}

/// Generate ETag for a file
async fn generate_etag(file_path: &Path) -> Result<String, WebServerError> {
    let metadata = tokio::fs::metadata(file_path)
        .await
        .map_err(|e| WebServerError::custom(format!("Failed to read file metadata: {}", e)))?;

    let modified = metadata
        .modified()
        .map_err(|e| WebServerError::custom(format!("Failed to get modification time: {}", e)))?;

    let timestamp = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| WebServerError::custom(format!("Invalid modification time: {}", e)))?
        .as_secs();

    Ok(format!("\"{}\"", timestamp))
}

/// Get MIME type for a file based on extension
fn mime_type_for_file(file_path: &Path) -> Option<String> {
    let extension = file_path.extension()?.to_str()?.to_lowercase();

    let mime_type = match extension.as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "txt" => "text/plain",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "eot" => "application/vnd.ms-fontobject",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        _ => "application/octet-stream",
    };

    Some(mime_type.to_string())
}

/// Static file serving middleware
pub fn static_files(config: StaticFileConfig) -> Arc<StaticFileHandler> {
    Arc::new(StaticFileHandler::new(config))
}

/// Create static file handler with default config
pub fn serve_static(root_dir: impl Into<PathBuf>) -> Arc<StaticFileHandler> {
    Arc::new(StaticFileHandler::new(StaticFileConfig {
        root_dir: root_dir.into(),
        ..Default::default()
    }))
}

/// Create static file handler with custom prefix
pub fn serve_static_with_prefix(
    root_dir: impl Into<PathBuf>,
    prefix: impl Into<String>,
) -> Arc<StaticFileHandler> {
    Arc::new(StaticFileHandler::new(StaticFileConfig {
        root_dir: root_dir.into(),
        url_prefix: prefix.into(),
        ..Default::default()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mime_type_detection() {
        assert_eq!(
            mime_type_for_file(Path::new("test.html")),
            Some("text/html".to_string())
        );
        assert_eq!(
            mime_type_for_file(Path::new("style.css")),
            Some("text/css".to_string())
        );
        assert_eq!(
            mime_type_for_file(Path::new("app.js")),
            Some("application/javascript".to_string())
        );
        assert_eq!(
            mime_type_for_file(Path::new("image.png")),
            Some("image/png".to_string())
        );
        assert_eq!(
            mime_type_for_file(Path::new("unknown.xyz")),
            Some("application/octet-stream".to_string())
        );
    }

    #[test]
    fn test_static_file_config() {
        let config = StaticFileConfig {
            root_dir: PathBuf::from("./public"),
            url_prefix: "/assets".to_string(),
            show_index: true,
            cache: false,
            ..Default::default()
        };

        assert_eq!(config.root_dir, PathBuf::from("./public"));
        assert_eq!(config.url_prefix, "/assets");
        assert!(config.show_index);
        assert!(!config.cache);
    }

    #[tokio::test]
    async fn test_static_handler_creation() {
        let handler = StaticFileHandler::default()
            .root_dir("./test_files")
            .url_prefix("/files");

        assert_eq!(handler.config.root_dir, PathBuf::from("./test_files"));
        assert_eq!(handler.config.url_prefix, "/files");
    }
}
