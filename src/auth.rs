//! Comprehensive authentication and authorization integration.
//!
//! This module provides deep integration with auth-framework, enabling seamless
//! authentication across all mountable interfaces and web server adapters.

use crate::error::{Result, WebServerError};
use crate::types::Request;
use auth_framework::{
    AuthConfig, AuthFramework, AuthResult, Credential,
    methods::{ApiKeyMethod, JwtMethod},
    tokens::AuthToken,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Central authentication context that can be shared across all mountable interfaces
#[derive(Clone)]
pub struct AuthContext {
    auth_framework: Arc<AuthFramework>,
    config: AuthContextConfig,
    user_sessions: Arc<RwLock<HashMap<String, UserSession>>>,
}

/// Configuration for the authentication context
#[derive(Clone, Debug)]
pub struct AuthContextConfig {
    /// Default token lifetime
    pub token_lifetime: Duration,
    /// Refresh token lifetime
    pub refresh_token_lifetime: Duration,
    /// Whether to require authentication for all routes by default
    pub require_auth_by_default: bool,
    /// Default permissions required for authenticated routes
    pub default_permissions: Vec<String>,
    /// JWT secret key
    pub jwt_secret: String,
    /// API key prefix
    pub api_key_prefix: String,
    /// Whether to enable multi-factor authentication
    pub enable_mfa: bool,
}

impl Default for AuthContextConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Duration::from_secs(3600), // 1 hour
            refresh_token_lifetime: Duration::from_secs(86400 * 7), // 7 days
            require_auth_by_default: false,
            default_permissions: vec!["read".to_string()],
            jwt_secret: "development-secret-change-in-production".to_string(),
            api_key_prefix: "wsa_".to_string(),
            enable_mfa: false,
        }
    }
}

/// User session information
#[derive(Clone, Debug)]
pub struct UserSession {
    pub user_id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
    pub token: Box<AuthToken>,
    pub last_activity: std::time::SystemTime,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Authentication middleware result
#[derive(Debug)]
pub enum AuthMiddlewareResult {
    /// Authentication succeeded, proceed with request
    Authenticated(UserSession),
    /// Authentication failed, deny request
    Denied(AuthError),
    /// No authentication attempted, proceed if not required
    Unauthenticated,
}

/// Authentication errors
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Authentication required")]
    AuthenticationRequired,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Insufficient permissions: required {required:?}, have {have:?}")]
    InsufficientPermissions {
        required: Vec<String>,
        have: Vec<String>,
    },
    #[error("Token expired")]
    TokenExpired,
    #[error("Multi-factor authentication required")]
    MfaRequired,
    #[error("Rate limited")]
    RateLimited,
    #[error("Internal auth error: {0}")]
    Internal(String),
}

impl AuthContext {
    /// Create a new authentication context
    pub async fn new(config: AuthContextConfig) -> Result<Self> {
        // Set environment for development/testing if not set
        if std::env::var("ENVIRONMENT").is_err() {
            unsafe {
                std::env::set_var("ENVIRONMENT", "development");
            }
        }

        // Configure auth framework
        let auth_config = AuthConfig::new()
            .token_lifetime(config.token_lifetime)
            .refresh_token_lifetime(config.refresh_token_lifetime);

        // Create auth framework instance
        let mut auth_framework = AuthFramework::new(auth_config);

        // Register JWT authentication method
        let jwt_method = JwtMethod::new()
            .secret_key(&config.jwt_secret)
            .issuer("web-server-abstraction");

        // Register the JWT method
        auth_framework.register_method("jwt", Box::new(jwt_method));

        // Register API key authentication method
        let api_key_method = ApiKeyMethod::new()
            .key_prefix(&config.api_key_prefix)
            .header_name("X-API-Key");

        // Register the API key method
        auth_framework.register_method("api-key", Box::new(api_key_method));

        // Initialize the framework
        auth_framework.initialize().await.map_err(|e| {
            WebServerError::AuthError(format!("Failed to initialize auth framework: {}", e))
        })?;

        Ok(Self {
            auth_framework: Arc::new(auth_framework),
            config,
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Authenticate a request and extract user session
    pub async fn authenticate_request(&self, request: &Request) -> AuthMiddlewareResult {
        // Try different authentication methods

        // 1. Try Bearer token (JWT)
        if let Some(auth_header) = request.headers.get("authorization")
            && let Some(token) = auth_header.strip_prefix("Bearer ")
        {
            return self.authenticate_bearer_token(token).await;
        }

        // 2. Try API key
        if let Some(api_key_str) = request.headers.get("x-api-key") {
            return self.authenticate_api_key(api_key_str).await;
        }

        // 3. Try session cookie
        if let Some(cookie_str) = request.headers.get("cookie")
            && let Some(session_token) = self.extract_session_token(cookie_str)
        {
            return self.authenticate_session_token(&session_token).await;
        }

        AuthMiddlewareResult::Unauthenticated
    }

    /// Authenticate using bearer token (JWT)
    async fn authenticate_bearer_token(&self, token: &str) -> AuthMiddlewareResult {
        let credential = Credential::jwt(token);

        match self.auth_framework.authenticate("jwt", credential).await {
            Ok(AuthResult::Success(auth_token)) => {
                let user_session = UserSession {
                    user_id: auth_token.user_id.clone(),
                    username: None, // Could be extracted from token claims
                    email: None,    // Could be extracted from token claims
                    permissions: auth_token.scopes.clone(),
                    roles: vec![], // Could be extracted from token claims
                    token: auth_token,
                    last_activity: std::time::SystemTime::now(),
                    metadata: HashMap::new(),
                };

                // Cache the session
                let mut sessions = self.user_sessions.write().await;
                sessions.insert(user_session.user_id.clone(), user_session.clone());

                AuthMiddlewareResult::Authenticated(user_session)
            }
            Ok(AuthResult::MfaRequired(_)) => AuthMiddlewareResult::Denied(AuthError::MfaRequired),
            Ok(AuthResult::Failure(_)) | Err(_) => {
                AuthMiddlewareResult::Denied(AuthError::InvalidCredentials)
            }
        }
    }

    /// Authenticate using API key
    async fn authenticate_api_key(&self, api_key: &str) -> AuthMiddlewareResult {
        let credential = Credential::api_key(api_key);

        match self
            .auth_framework
            .authenticate("api-key", credential)
            .await
        {
            Ok(AuthResult::Success(auth_token)) => {
                let user_session = UserSession {
                    user_id: auth_token.user_id.clone(),
                    username: None,
                    email: None,
                    permissions: auth_token.scopes.clone(),
                    roles: vec![],
                    token: auth_token,
                    last_activity: std::time::SystemTime::now(),
                    metadata: HashMap::new(),
                };

                AuthMiddlewareResult::Authenticated(user_session)
            }
            Ok(AuthResult::MfaRequired(_)) => AuthMiddlewareResult::Denied(AuthError::MfaRequired),
            Ok(AuthResult::Failure(_)) | Err(_) => {
                AuthMiddlewareResult::Denied(AuthError::InvalidCredentials)
            }
        }
    }

    /// Authenticate using session token
    async fn authenticate_session_token(&self, session_token: &str) -> AuthMiddlewareResult {
        // Check if we have a cached session
        let sessions = self.user_sessions.read().await;
        if let Some(session) = sessions
            .values()
            .find(|s| s.token.token_id == session_token)
        {
            // Check if session is still valid
            if self.is_session_valid(session) {
                return AuthMiddlewareResult::Authenticated(session.clone());
            }
        }
        drop(sessions);

        // Session not found or invalid
        AuthMiddlewareResult::Denied(AuthError::InvalidCredentials)
    }

    /// Extract session token from cookie string
    fn extract_session_token(&self, cookie_str: &str) -> Option<String> {
        for cookie in cookie_str.split(';') {
            let cookie = cookie.trim();
            if let Some((name, value)) = cookie.split_once('=')
                && name.trim() == "session_token"
            {
                return Some(value.trim().to_string());
            }
        }
        None
    }

    /// Check if a session is still valid
    fn is_session_valid(&self, session: &UserSession) -> bool {
        // Check if session has expired based on last activity
        let now = std::time::SystemTime::now();
        if let Ok(duration) = now.duration_since(session.last_activity) {
            duration < self.config.token_lifetime
        } else {
            false
        }
    }

    /// Check if user has required permissions
    pub async fn check_permissions(
        &self,
        user_session: &UserSession,
        required_permissions: &[String],
    ) -> bool {
        if required_permissions.is_empty() {
            return true;
        }

        // Check if user has all required permissions
        for required in required_permissions {
            if !user_session.permissions.contains(required) {
                return false;
            }
        }

        true
    }

    /// Create an authentication token for a user
    pub async fn create_token(&self, user_id: &str, permissions: Vec<String>) -> Result<String> {
        let token = self
            .auth_framework
            .create_auth_token(user_id, permissions, "jwt", None)
            .await
            .map_err(|e| WebServerError::AuthError(format!("Failed to create token: {}", e)))?;

        Ok(token.access_token)
    }

    /// Create an API key for a user
    pub async fn create_api_key(
        &self,
        user_id: &str,
        expires_in: Option<Duration>,
    ) -> Result<String> {
        let api_key = self
            .auth_framework
            .create_api_key(user_id, expires_in)
            .await
            .map_err(|e| WebServerError::AuthError(format!("Failed to create API key: {}", e)))?;

        Ok(api_key)
    }

    /// Revoke a token or API key
    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        // Implementation would depend on auth-framework's revocation capabilities
        // For now, we'll remove from our local cache
        let mut sessions = self.user_sessions.write().await;
        sessions.retain(|_, session| session.token.access_token != token);
        Ok(())
    }

    /// Get user session by user ID
    pub async fn get_user_session(&self, user_id: &str) -> Option<UserSession> {
        let sessions = self.user_sessions.read().await;
        sessions.get(user_id).cloned()
    }

    /// Get configuration
    pub fn config(&self) -> &AuthContextConfig {
        &self.config
    }

    /// Get the underlying auth framework (for advanced usage)
    pub fn auth_framework(&self) -> &Arc<AuthFramework> {
        &self.auth_framework
    }
}

/// Authentication requirements for routes
#[derive(Clone, Debug)]
pub struct AuthRequirements {
    /// Whether authentication is required
    pub required: bool,
    /// Required permissions
    pub permissions: Vec<String>,
    /// Required roles
    pub roles: Vec<String>,
    /// Whether to allow API key authentication
    pub allow_api_key: bool,
    /// Whether to allow JWT authentication
    pub allow_jwt: bool,
    /// Whether to allow session authentication
    pub allow_session: bool,
}

impl Default for AuthRequirements {
    fn default() -> Self {
        Self {
            required: false,
            permissions: vec![],
            roles: vec![],
            allow_api_key: true,
            allow_jwt: true,
            allow_session: true,
        }
    }
}

impl AuthRequirements {
    /// Create auth requirements that require authentication
    pub fn required() -> Self {
        Self {
            required: true,
            ..Default::default()
        }
    }

    /// Add required permissions
    pub fn with_permissions(mut self, permissions: Vec<String>) -> Self {
        self.permissions = permissions;
        self
    }

    /// Add required roles
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Only allow JWT authentication
    pub fn jwt_only(mut self) -> Self {
        self.allow_api_key = false;
        self.allow_session = false;
        self
    }

    /// Only allow API key authentication
    pub fn api_key_only(mut self) -> Self {
        self.allow_jwt = false;
        self.allow_session = false;
        self
    }
}

/// Middleware function for authentication
pub async fn auth_middleware(
    auth_context: &AuthContext,
    auth_requirements: &AuthRequirements,
    request: &Request,
) -> Result<Option<UserSession>> {
    let auth_result = auth_context.authenticate_request(request).await;

    match auth_result {
        AuthMiddlewareResult::Authenticated(user_session) => {
            // Check permissions if required
            if !auth_requirements.permissions.is_empty()
                && !auth_context
                    .check_permissions(&user_session, &auth_requirements.permissions)
                    .await
            {
                return Err(WebServerError::AuthError(format!(
                    "Insufficient permissions: required {:?}, have {:?}",
                    auth_requirements.permissions, user_session.permissions
                )));
            }

            // Check roles if required
            if !auth_requirements.roles.is_empty() {
                let has_required_role = auth_requirements
                    .roles
                    .iter()
                    .any(|role| user_session.roles.contains(role));
                if !has_required_role {
                    return Err(WebServerError::AuthError(format!(
                        "Insufficient roles: required one of {:?}, have {:?}",
                        auth_requirements.roles, user_session.roles
                    )));
                }
            }

            Ok(Some(user_session))
        }
        AuthMiddlewareResult::Denied(auth_error) => {
            Err(WebServerError::AuthError(auth_error.to_string()))
        }
        AuthMiddlewareResult::Unauthenticated => {
            if auth_requirements.required {
                Err(WebServerError::AuthError(
                    "Authentication required".to_string(),
                ))
            } else {
                Ok(None)
            }
        }
    }
}

/// Extension trait to add authentication information to requests
pub trait RequestAuthExt {
    /// Get the authenticated user session from the request
    fn user_session(&self) -> Option<&UserSession>;

    /// Get the user ID from the authenticated session
    fn user_id(&self) -> Option<&str>;

    /// Check if the request is authenticated
    fn is_authenticated(&self) -> bool;

    /// Check if the user has a specific permission
    fn has_permission(&self, permission: &str) -> bool;

    /// Check if the user has a specific role
    fn has_role(&self, role: &str) -> bool;
}

// Note: Implementation of RequestAuthExt would be done through request extensions
// in the actual middleware integration with specific frameworks

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_auth_context_creation() {
        let config = AuthContextConfig::default();
        let auth_context = AuthContext::new(config).await.unwrap();

        assert!(!auth_context.config().require_auth_by_default);
        assert_eq!(auth_context.config().default_permissions, vec!["read"]);
    }

    #[tokio::test]
    async fn test_auth_requirements() {
        let requirements = AuthRequirements::required()
            .with_permissions(vec!["admin.read".to_string(), "admin.write".to_string()])
            .jwt_only();

        assert!(requirements.required);
        assert_eq!(requirements.permissions.len(), 2);
        assert!(!requirements.allow_api_key);
        assert!(requirements.allow_jwt);
    }

    #[tokio::test]
    async fn test_token_creation() {
        let config = AuthContextConfig::default();
        let auth_context = AuthContext::new(config).await.unwrap();

        let token = auth_context
            .create_token("test_user", vec!["read".to_string(), "write".to_string()])
            .await
            .unwrap();

        assert!(!token.is_empty());
    }
}
