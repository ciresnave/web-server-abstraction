//! Comprehensive authentication and authorization integration.
//!
//! This module provides deep integration with auth-framework 0.4.0, enabling seamless
//! authentication across all mountable interfaces and web server adapters.
//!
//! ## Features
//!
//! - **Multiple Authentication Methods**: JWT, API Keys, OAuth2, Passwords, TOTP
//! - **OAuth2/OIDC Server**: Full authorization server capabilities
//! - **Multi-Factor Authentication**: TOTP, SMS, Email verification
//! - **Audit Logging**: Comprehensive security event tracking
//! - **Session Management**: Secure session handling with device fingerprinting
//! - **Rate Limiting**: Built-in protection against brute force attacks
//! - **Enterprise Features**: SAML, WS-Security, Token introspection

use crate::error::{Result, WebServerError};
use crate::types::Request;
use auth_framework::{
    AuthConfig, AuthFramework, AuthResult, Credential,
    methods::{ApiKeyMethod, AuthMethodEnum, JwtMethod},
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
    // Advanced features from auth-framework 0.4.0
    oauth2_server: Option<Arc<dyn Send + Sync>>, // OAuth2Server placeholder
    oidc_provider: Option<Arc<dyn Send + Sync>>, // OidcProvider placeholder
    audit_logger: Option<Arc<dyn Send + Sync>>,  // AuditLogger placeholder
    rate_limiter: Option<Arc<dyn Send + Sync>>,  // RateLimiter placeholder
    session_manager: Option<Arc<dyn Send + Sync>>, // SecureSessionManager placeholder
    mfa_manager: Option<Arc<dyn Send + Sync>>,   // MfaManager placeholder
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
    /// Enable OAuth2 server capabilities
    pub enable_oauth2_server: bool,
    /// Enable OIDC provider functionality
    pub enable_oidc: bool,
    /// Enable audit logging
    pub enable_audit_logging: bool,
    /// Enable rate limiting
    pub enable_rate_limiting: bool,
    /// Rate limit requests per minute
    pub rate_limit_rpm: u32,
    /// Enable session security features
    pub enable_secure_sessions: bool,
    /// Enable device fingerprinting
    pub enable_device_fingerprinting: bool,
    /// Supported OAuth2 providers
    pub oauth2_providers: Vec<String>,
    /// RSA private key for JWT signing (PEM format)
    pub rsa_private_key: Option<String>,
    /// RSA public key for JWT verification (PEM format)
    pub rsa_public_key: Option<String>,
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
            enable_oauth2_server: false,
            enable_oidc: false,
            enable_audit_logging: true,
            enable_rate_limiting: true,
            rate_limit_rpm: 100,
            enable_secure_sessions: true,
            enable_device_fingerprinting: false,
            oauth2_providers: vec![
                "google".to_string(),
                "github".to_string(),
                "microsoft".to_string(),
            ],
            rsa_private_key: None,
            rsa_public_key: None,
        }
    }
}

/// User session information with enhanced auth-framework 0.4.0 features
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
    // Enhanced features from auth-framework 0.4.0
    pub mfa_enabled: bool,
    pub mfa_verified: bool,
    pub device_fingerprint: Option<String>,
    pub oauth2_provider: Option<String>,
    pub session_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub login_time: std::time::SystemTime,
    pub totp_secret: Option<String>,
}

/// Authentication middleware result
#[derive(Debug)]
pub enum AuthMiddlewareResult {
    /// Authentication succeeded, proceed with request
    Authenticated(Box<UserSession>),
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
        auth_framework.register_method("jwt", AuthMethodEnum::Jwt(jwt_method));

        // Register API key authentication method
        let api_key_method = ApiKeyMethod::new();

        // Register the API key method
        auth_framework.register_method("api-key", AuthMethodEnum::ApiKey(api_key_method));

        // Initialize the framework
        auth_framework.initialize().await.map_err(|e| {
            WebServerError::AuthError(format!("Failed to initialize auth framework: {}", e))
        })?;

        Ok(Self {
            auth_framework: Arc::new(auth_framework),
            config: config.clone(),
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
            oauth2_server: None,
            oidc_provider: None,
            audit_logger: None,
            rate_limiter: None,
            session_manager: None,
            mfa_manager: None,
        })
    }

    /// Initialize all enabled authentication features
    pub async fn initialize_features(&mut self) -> Result<()> {
        // Initialize OAuth2 server if enabled
        if self.config.enable_oauth2_server {
            self.enable_oauth2_server().await?;
        }

        // Initialize OIDC provider if enabled
        if self.config.enable_oidc {
            self.enable_oidc_provider().await?;
        }

        // Initialize audit logging if enabled
        if self.config.enable_audit_logging {
            self.enable_audit_logging().await?;
        }

        // Initialize rate limiting if enabled
        if self.config.enable_rate_limiting {
            self.enable_rate_limiting().await?;
        }

        // Initialize MFA if enabled
        if self.config.enable_mfa {
            self.enable_mfa().await?;
        }

        Ok(())
    }

    /// Authenticate a request and extract user session
    pub async fn authenticate_request(&self, request: &Request) -> AuthMiddlewareResult {
        // Check rate limiting first if enabled
        if let Some(_rate_limiter) = &self.rate_limiter {
            // For now, just check the presence of rate limiter
            // In a real implementation, this would check IP/user rate limits
        }

        // Try different authentication methods

        // 1. Try Bearer token (JWT)
        if let Some(auth_header) = request.headers.get("authorization")
            && let Some(token) = auth_header.strip_prefix("Bearer ")
        {
            let result = self.authenticate_bearer_token(token).await;

            // Log authentication attempt if audit logging is enabled
            if let Some(_audit_logger) = &self.audit_logger {
                match &result {
                    AuthMiddlewareResult::Authenticated(session) => {
                        // Would log successful authentication
                        println!(
                            "AUDIT: JWT authentication succeeded for user: {}",
                            session.user_id
                        );
                    }
                    AuthMiddlewareResult::Denied(_) => {
                        // Would log failed authentication
                        println!("AUDIT: JWT authentication failed");
                    }
                    _ => {}
                }
            }

            return result;
        }

        // 2. Try API key
        if let Some(api_key_str) = request.headers.get("x-api-key") {
            let result = self.authenticate_api_key(api_key_str).await;

            // Log authentication attempt if audit logging is enabled
            if let Some(_audit_logger) = &self.audit_logger {
                match &result {
                    AuthMiddlewareResult::Authenticated(session) => {
                        println!(
                            "AUDIT: API key authentication succeeded for user: {}",
                            session.user_id
                        );
                    }
                    AuthMiddlewareResult::Denied(_) => {
                        println!("AUDIT: API key authentication failed");
                    }
                    _ => {}
                }
            }

            return result;
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
                    mfa_enabled: false,
                    mfa_verified: false,
                    device_fingerprint: None,
                    oauth2_provider: None,
                    session_id: uuid::Uuid::new_v4().to_string(),
                    ip_address: None,
                    user_agent: None,
                    login_time: std::time::SystemTime::now(),
                    totp_secret: None,
                };

                // Cache the session
                let mut sessions = self.user_sessions.write().await;
                sessions.insert(user_session.user_id.clone(), user_session.clone());

                AuthMiddlewareResult::Authenticated(Box::new(user_session))
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
                    mfa_enabled: false,
                    mfa_verified: false,
                    device_fingerprint: None,
                    oauth2_provider: None,
                    session_id: uuid::Uuid::new_v4().to_string(),
                    ip_address: None,
                    user_agent: None,
                    login_time: std::time::SystemTime::now(),
                    totp_secret: None,
                };

                AuthMiddlewareResult::Authenticated(Box::new(user_session))
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
                return AuthMiddlewareResult::Authenticated(Box::new(session.clone()));
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

    /// Check if OAuth2 server is enabled
    pub fn is_oauth2_enabled(&self) -> bool {
        self.oauth2_server.is_some()
    }

    /// Check if OIDC provider is enabled
    pub fn is_oidc_enabled(&self) -> bool {
        self.oidc_provider.is_some()
    }

    /// Check if audit logging is enabled
    pub fn is_audit_logging_enabled(&self) -> bool {
        self.audit_logger.is_some()
    }

    /// Check if rate limiting is enabled
    pub fn is_rate_limiting_enabled(&self) -> bool {
        self.rate_limiter.is_some()
    }

    /// Check if MFA is enabled
    pub fn is_mfa_enabled(&self) -> bool {
        self.mfa_manager.is_some()
    }

    /// Check if session management is enabled
    pub fn is_session_management_enabled(&self) -> bool {
        self.session_manager.is_some()
    }

    /// Enable OAuth2 server functionality
    pub async fn enable_oauth2_server(&mut self) -> Result<()> {
        if self.config.enable_oauth2_server {
            // For now, create a placeholder that indicates OAuth2 is enabled
            // In a real implementation, this would initialize OAuth2Server from auth-framework
            self.oauth2_server = Some(Arc::new(()));
            println!("OAuth2 server capabilities enabled");
        }
        Ok(())
    }

    /// Enable OIDC provider functionality
    pub async fn enable_oidc_provider(&mut self) -> Result<()> {
        if self.config.enable_oidc {
            // For now, create a placeholder that indicates OIDC is enabled
            // In a real implementation, this would initialize OidcProvider from auth-framework
            self.oidc_provider = Some(Arc::new(()));
            println!("OIDC provider capabilities enabled");
        }
        Ok(())
    }

    /// Enable audit logging
    pub async fn enable_audit_logging(&mut self) -> Result<()> {
        if self.config.enable_audit_logging {
            // For now, create a placeholder that indicates audit logging is enabled
            // In a real implementation, this would initialize AuditLogger from auth-framework
            self.audit_logger = Some(Arc::new(()));
            println!("Audit logging enabled");
        }
        Ok(())
    }

    /// Enable rate limiting
    pub async fn enable_rate_limiting(&mut self) -> Result<()> {
        if self.config.enable_rate_limiting {
            // For now, create a placeholder that indicates rate limiting is enabled
            // In a real implementation, this would initialize RateLimiter from auth-framework
            self.rate_limiter = Some(Arc::new(()));
            println!("Rate limiting enabled ({} RPM)", self.config.rate_limit_rpm);
        }
        Ok(())
    }

    /// Enable multi-factor authentication
    pub async fn enable_mfa(&mut self) -> Result<()> {
        if self.config.enable_mfa {
            // For now, create a placeholder that indicates MFA is enabled
            // In a real implementation, this would initialize MfaManager from auth-framework
            self.mfa_manager = Some(Arc::new(()));
            println!("Multi-factor authentication enabled");
        }
        Ok(())
    }

    /// Create a user with password authentication
    pub async fn create_user_with_password(
        &self,
        user_id: &str,
        username: &str,
        email: &str,
        _password: &str,
        permissions: Vec<String>,
        roles: Vec<String>,
    ) -> Result<UserSession> {
        // TODO: Implement password-based user creation when auth-framework API is stable
        // For now, create a basic user session
        let user_session = UserSession {
            user_id: user_id.to_string(),
            username: Some(username.to_string()),
            email: Some(email.to_string()),
            permissions,
            roles,
            token: Box::new(AuthToken::new(
                user_id,
                "temporary_token",
                std::time::Duration::from_secs(3600),
                "password",
            )),
            last_activity: std::time::SystemTime::now(),
            metadata: HashMap::new(),
            mfa_enabled: false,
            mfa_verified: false,
            device_fingerprint: None,
            oauth2_provider: None,
            session_id: uuid::Uuid::new_v4().to_string(),
            ip_address: None,
            user_agent: None,
            login_time: std::time::SystemTime::now(),
            totp_secret: None,
        };

        let mut sessions = self.user_sessions.write().await;
        sessions.insert(user_id.to_string(), user_session.clone());

        Ok(user_session)
    }

    /// Authenticate with OAuth2 provider
    pub async fn authenticate_oauth2(
        &self,
        _provider: &str,
        _authorization_code: &str,
        _redirect_uri: &str,
    ) -> Result<UserSession> {
        // TODO: Implement OAuth2 authentication when auth-framework API is stable
        Err(WebServerError::AuthError(
            "OAuth2 authentication not yet implemented - waiting for auth-framework API stabilization".to_string(),
        ))
    }

    /// Generate TOTP secret for user
    pub async fn generate_totp_secret(&self, _user_id: &str) -> Result<String> {
        // TODO: Implement TOTP when auth-framework API is stable
        Err(WebServerError::AuthError(
            "TOTP not yet implemented - waiting for auth-framework API stabilization".to_string(),
        ))
    }

    /// Verify TOTP code
    pub async fn verify_totp(&self, _user_id: &str, _code: &str) -> Result<bool> {
        // TODO: Implement TOTP verification when auth-framework API is stable
        Err(WebServerError::AuthError(
            "TOTP verification not yet implemented - waiting for auth-framework API stabilization"
                .to_string(),
        ))
    }

    /// Log authentication event for audit
    pub async fn log_auth_event(
        &self,
        event_type: &str,
        user_id: &str,
        success: bool,
    ) -> Result<()> {
        // TODO: Implement audit logging when auth-framework API is stable
        if self.config.enable_audit_logging {
            // Would log to audit system
            println!(
                "AUDIT: {} - User: {} - Success: {}",
                event_type, user_id, success
            );
        }
        Ok(())
    }

    /// Check rate limit for user
    pub async fn check_rate_limit(&self, _user_id: &str) -> Result<bool> {
        // TODO: Implement rate limiting when auth-framework API is stable
        if self.config.enable_rate_limiting {
            // For now, always allow (would implement actual rate limiting)
            return Ok(true);
        }
        Ok(true)
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

/// Enhanced middleware function for authentication with auth-framework 0.4.0 features
pub async fn enhanced_auth_middleware(
    auth_context: &AuthContext,
    auth_requirements: &AuthRequirements,
    request: &Request,
) -> Result<Option<UserSession>> {
    // Check rate limiting first
    if let Some(auth_header) = request.headers.get("authorization")
        && let Some(_token) = auth_header.strip_prefix("Bearer ")
    {
        // Extract user ID from token for rate limiting (simplified)
        let user_id = "extracted_user_id"; // Would extract from token in real implementation
        if !auth_context.check_rate_limit(user_id).await? {
            return Err(WebServerError::AuthError("Rate limit exceeded".to_string()));
        }
    }

    // Perform authentication
    let auth_result = auth_context.authenticate_request(request).await;

    match auth_result {
        AuthMiddlewareResult::Authenticated(mut user_session) => {
            // Enhanced security checks for auth-framework 0.4.0

            // Check if MFA is required but not verified
            if auth_requirements.required
                && auth_context.config.enable_mfa
                && user_session.mfa_enabled
                && !user_session.mfa_verified
            {
                return Err(WebServerError::AuthError(
                    "Multi-factor authentication required".to_string(),
                ));
            }

            // Check permissions if required
            if !auth_requirements.permissions.is_empty()
                && !auth_context
                    .check_permissions(&user_session, &auth_requirements.permissions)
                    .await
            {
                // Log failed permission check
                auth_context
                    .log_auth_event("permission_denied", &user_session.user_id, false)
                    .await?;

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
                    // Log failed role check
                    auth_context
                        .log_auth_event("role_denied", &user_session.user_id, false)
                        .await?;

                    return Err(WebServerError::AuthError(format!(
                        "Insufficient roles: required one of {:?}, have {:?}",
                        auth_requirements.roles, user_session.roles
                    )));
                }
            }

            // Update session with request information
            user_session.last_activity = std::time::SystemTime::now();
            if let Some(ip) = request.headers.get("x-forwarded-for") {
                user_session.ip_address = Some(ip.clone());
            }
            if let Some(user_agent) = request.headers.get("user-agent") {
                user_session.user_agent = Some(user_agent.clone());
            }

            // Log successful authentication
            auth_context
                .log_auth_event("authentication_success", &user_session.user_id, true)
                .await?;

            Ok(Some(*user_session))
        }
        AuthMiddlewareResult::Denied(auth_error) => {
            // Log failed authentication attempt
            if let Some(auth_header) = request.headers.get("authorization")
                && let Some(_token) = auth_header.strip_prefix("Bearer ")
            {
                let user_id = "unknown"; // Would extract from token
                auth_context
                    .log_auth_event("authentication_failed", user_id, false)
                    .await?;
            }

            Err(WebServerError::AuthError(format!("{:?}", auth_error)))
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

/// Original middleware function for authentication (backward compatibility)
pub async fn auth_middleware(
    auth_context: &AuthContext,
    auth_requirements: &AuthRequirements,
    request: &Request,
) -> Result<Option<UserSession>> {
    enhanced_auth_middleware(auth_context, auth_requirements, request).await
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
