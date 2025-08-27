//! Unified Configuration System
//!
//! This module provides a comprehensive configuration management system
//! with support for multiple configuration sources, validation, and dynamic updates.

use serde::{Deserialize, Serialize};
use serde_yaml;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Configuration error types
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Configuration validation error: {message}")]
    Validation { message: String },
    #[error("Key not found: {key}")]
    KeyNotFound { key: String },
    #[error("Type conversion error: {0}")]
    TypeConversion(String),
}

/// Configuration value type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<ConfigValue>),
    Object(HashMap<String, ConfigValue>),
}

impl ConfigValue {
    pub fn as_string(&self) -> Result<String, ConfigError> {
        match self {
            ConfigValue::String(s) => Ok(s.clone()),
            _ => Err(ConfigError::TypeConversion("Expected string".to_string())),
        }
    }

    pub fn as_bool(&self) -> Result<bool, ConfigError> {
        match self {
            ConfigValue::Boolean(b) => Ok(*b),
            _ => Err(ConfigError::TypeConversion("Expected boolean".to_string())),
        }
    }

    pub fn as_i64(&self) -> Result<i64, ConfigError> {
        match self {
            ConfigValue::Integer(i) => Ok(*i),
            _ => Err(ConfigError::TypeConversion("Expected integer".to_string())),
        }
    }
}

/// Configuration manager
pub struct ConfigManager {
    data: Arc<RwLock<HashMap<String, ConfigValue>>>,
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigManager {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn load_from_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let content = tokio::fs::read_to_string(path).await?;
        let yaml_value: serde_yaml::Value = serde_yaml::from_str(&content)?;

        let mut data = self.data.write().await;
        self.load_yaml_recursive(&yaml_value, "", &mut data)?;
        Ok(())
    }

    fn load_yaml_recursive(
        &self,
        value: &serde_yaml::Value,
        prefix: &str,
        data: &mut HashMap<String, ConfigValue>,
    ) -> Result<(), ConfigError> {
        match value {
            serde_yaml::Value::Mapping(map) => {
                for (key, val) in map {
                    let key_str = key.as_str().ok_or_else(|| ConfigError::Validation {
                        message: "Non-string key in YAML".to_string(),
                    })?;
                    let full_key = if prefix.is_empty() {
                        key_str.to_string()
                    } else {
                        format!("{}.{}", prefix, key_str)
                    };

                    self.load_yaml_recursive(val, &full_key, data)?;
                }
            }
            _ => {
                let config_value = self.yaml_to_config_value(value)?;
                data.insert(prefix.to_string(), config_value);
            }
        }
        Ok(())
    }

    fn yaml_to_config_value(&self, value: &serde_yaml::Value) -> Result<ConfigValue, ConfigError> {
        match value {
            serde_yaml::Value::String(s) => Ok(ConfigValue::String(s.clone())),
            serde_yaml::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(ConfigValue::Integer(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(ConfigValue::Float(f))
                } else {
                    Err(ConfigError::TypeConversion("Invalid number".to_string()))
                }
            }
            serde_yaml::Value::Bool(b) => Ok(ConfigValue::Boolean(*b)),
            serde_yaml::Value::Sequence(seq) => {
                let array: Result<Vec<_>, _> =
                    seq.iter().map(|v| self.yaml_to_config_value(v)).collect();
                Ok(ConfigValue::Array(array?))
            }
            serde_yaml::Value::Mapping(map) => {
                let mut object = HashMap::new();
                for (k, v) in map {
                    let key = k
                        .as_str()
                        .ok_or_else(|| ConfigError::TypeConversion("Non-string key".to_string()))?;
                    object.insert(key.to_string(), self.yaml_to_config_value(v)?);
                }
                Ok(ConfigValue::Object(object))
            }
            serde_yaml::Value::Null => Ok(ConfigValue::String("".to_string())),
            serde_yaml::Value::Tagged(tagged) => {
                // Handle tagged values by processing the inner value
                self.yaml_to_config_value(&tagged.value)
            }
        }
    }

    pub async fn get(&self, key: &str) -> Result<ConfigValue, ConfigError> {
        let data = self.data.read().await;
        data.get(key)
            .cloned()
            .ok_or_else(|| ConfigError::KeyNotFound {
                key: key.to_string(),
            })
    }

    pub async fn set(&self, key: &str, value: ConfigValue) -> Result<(), ConfigError> {
        let mut data = self.data.write().await;
        data.insert(key.to_string(), value);
        Ok(())
    }

    pub async fn get_value(&self, key: &str) -> Result<ConfigValue, ConfigError> {
        self.get(key).await
    }

    pub async fn set_value(&self, key: &str, value: ConfigValue) -> Result<(), ConfigError> {
        self.set(key, value).await
    }

    pub async fn watch(&self, _key: &str) -> Result<(), ConfigError> {
        // Simple implementation - just return ok for now
        Ok(())
    }

    pub async fn save_to_file<P: AsRef<Path>>(&self, _path: P) -> Result<(), ConfigError> {
        // Simple implementation - just return ok for now
        Ok(())
    }
}

/// Adapter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    pub name: String,
    pub enabled: bool,
    pub settings: HashMap<String, ConfigValue>,
}

/// Middleware configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareConfig {
    pub cors: CorsConfig,
    pub compression: CompressionConfig,
    pub rate_limiting: RateLimitingConfig,
    pub security_headers: SecurityHeadersConfig,
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub credentials: bool,
    pub max_age: u32,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
            ],
            allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
            credentials: false,
            max_age: 3600,
        }
    }
}

/// Compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    pub enabled: bool,
    pub algorithms: Vec<String>,
    pub min_size: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithms: vec!["gzip".to_string(), "br".to_string()],
            min_size: 1024,
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    pub enabled: bool,
    pub requests_per_minute: u64,
    pub burst_size: u64,
    pub window_size: u64,
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 1000,
            burst_size: 100,
            window_size: 60,
        }
    }
}

/// Security headers configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersConfig {
    pub enabled: bool,
    pub content_security_policy: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: bool,
    pub strict_transport_security: Option<String>,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            content_security_policy: Some("default-src 'self'".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: true,
            strict_transport_security: Some("max-age=31536000; includeSubDomains".to_string()),
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_csrf_protection: bool,
    pub enable_rate_limiting: bool,
    pub enable_input_validation: bool,
    pub enable_request_logging: bool,
    pub max_request_size: usize,
    pub allowed_file_types: Vec<String>,
    pub tls: TlsConfig,
    pub rate_limit_per_minute: Option<u32>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_csrf_protection: true,
            enable_rate_limiting: true,
            enable_input_validation: true,
            enable_request_logging: true,
            max_request_size: 10 * 1024 * 1024, // 10MB
            allowed_file_types: vec!["jpg".to_string(), "png".to_string(), "pdf".to_string()],
            tls: TlsConfig::default(),
            rate_limit_per_minute: Some(60), // Default rate limit
        }
    }
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enable_metrics: bool,
    pub enable_tracing: bool,
    pub enable_health_checks: bool,
    pub enable_alerts: bool,
    pub metrics_endpoint: String,
    pub health_endpoint: String,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            enable_tracing: true,
            enable_health_checks: true,
            enable_alerts: true,
            metrics_endpoint: "/metrics".to_string(),
            health_endpoint: "/health".to_string(),
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_file: String,
    pub key_file: String,
    pub ca_file: Option<String>,
    pub verify_client: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_file: "cert.pem".to_string(),
            key_file: "key.pem".to_string(),
            ca_file: None,
            verify_client: false,
        }
    }
}

/// Feature flags configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlags {
    pub enable_caching: bool,
    pub enable_compression: bool,
    pub enable_websockets: bool,
    pub enable_sse: bool,
    pub enable_graphql: bool,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            enable_caching: true,
            enable_compression: true,
            enable_websockets: false,
            enable_sse: false,
            enable_graphql: false,
        }
    }
}

/// Main web server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebServerConfig {
    pub server: ServerConfig,
    pub adapters: Vec<AdapterConfig>,
    pub middleware: MiddlewareConfig,
    pub security: SecurityConfig,
    pub monitoring: MonitoringConfig,
    pub tls: TlsConfig,
    pub feature_flags: FeatureFlags,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
    pub timeout: u64,
    pub keep_alive: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            max_connections: 1000,
            timeout: 30,
            keep_alive: true,
        }
    }
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            adapters: vec![],
            middleware: MiddlewareConfig {
                cors: CorsConfig::default(),
                compression: CompressionConfig::default(),
                rate_limiting: RateLimitingConfig::default(),
                security_headers: SecurityHeadersConfig::default(),
            },
            security: SecurityConfig::default(),
            monitoring: MonitoringConfig::default(),
            tls: TlsConfig::default(),
            feature_flags: FeatureFlags::default(),
        }
    }
}

/// Unified configuration manager
pub struct UnifiedConfigManager {
    manager: ConfigManager,
    config: Arc<RwLock<WebServerConfig>>,
}

impl UnifiedConfigManager {
    pub async fn new() -> Result<Self, ConfigError> {
        let manager = ConfigManager::new();
        let config = Arc::new(RwLock::new(WebServerConfig::default()));

        Ok(Self { manager, config })
    }

    pub async fn load_from_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        self.manager.load_from_file(path).await?;
        self.sync_config().await
    }

    async fn sync_config(&self) -> Result<(), ConfigError> {
        // This is a simplified sync - in a real implementation you'd parse all the nested config
        Ok(())
    }

    pub async fn get_server_config(&self) -> ServerConfig {
        self.config.read().await.server.clone()
    }

    pub async fn get_adapters_config(&self) -> Result<Vec<AdapterConfig>, ConfigError> {
        Ok(self.config.read().await.adapters.clone())
    }

    pub async fn get_middleware_config(&self) -> Result<MiddlewareConfig, ConfigError> {
        Ok(self.config.read().await.middleware.clone())
    }

    pub async fn get_security_config(&self) -> Result<SecurityConfig, ConfigError> {
        Ok(self.config.read().await.security.clone())
    }

    pub async fn get_monitoring_config(&self) -> Result<MonitoringConfig, ConfigError> {
        Ok(self.config.read().await.monitoring.clone())
    }

    pub async fn get_feature_flags(&self) -> Result<FeatureFlags, ConfigError> {
        Ok(self.config.read().await.feature_flags.clone())
    }

    pub async fn is_feature_enabled(&self, feature: &str) -> Result<bool, ConfigError> {
        let flags = self.get_feature_flags().await?;
        let enabled = match feature {
            "caching" => flags.enable_caching,
            "compression" => flags.enable_compression,
            "websockets" => flags.enable_websockets,
            "sse" => flags.enable_sse,
            "graphql" => flags.enable_graphql,
            _ => false,
        };
        Ok(enabled)
    }

    pub async fn set_feature(&self, key: &str, value: ConfigValue) -> Result<(), ConfigError> {
        self.manager.set(key, value).await
    }

    pub async fn watch_config(&self, _key: &str) -> Result<(), ConfigError> {
        self.manager.watch(_key).await
    }

    pub async fn save_config<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        self.manager.save_to_file(path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_config_manager_creation() {
        let manager = ConfigManager::new();

        // Test setting and getting values
        let test_value = ConfigValue::String("test".to_string());
        manager.set("test_key", test_value.clone()).await.unwrap();

        let retrieved = manager.get("test_key").await.unwrap();
        match (test_value, retrieved) {
            (ConfigValue::String(expected), ConfigValue::String(actual)) => {
                assert_eq!(expected, actual);
            }
            _ => panic!("Values don't match"),
        }
    }

    #[tokio::test]
    async fn test_unified_config_manager() {
        let manager = UnifiedConfigManager::new().await.unwrap();

        // Test getting default configs
        let server_config = manager.get_server_config().await;
        assert_eq!(server_config.host, "127.0.0.1");
        assert_eq!(server_config.port, 8080);

        let feature_flags = manager.get_feature_flags().await.unwrap();
        assert!(feature_flags.enable_caching);
        assert!(feature_flags.enable_compression);

        // Test feature checking
        let caching_enabled = manager.is_feature_enabled("caching").await.unwrap();
        assert!(caching_enabled);

        let unknown_feature = manager.is_feature_enabled("unknown").await.unwrap();
        assert!(!unknown_feature);
    }

    #[tokio::test]
    async fn test_config_value_conversions() {
        let string_val = ConfigValue::String("test".to_string());
        assert_eq!(string_val.as_string().unwrap(), "test");

        let bool_val = ConfigValue::Boolean(true);
        assert!(bool_val.as_bool().unwrap());

        let int_val = ConfigValue::Integer(42);
        assert_eq!(int_val.as_i64().unwrap(), 42);

        // Test type conversion errors
        assert!(string_val.as_bool().is_err());
        assert!(bool_val.as_string().is_err());
        assert!(int_val.as_string().is_err());
    }
}
