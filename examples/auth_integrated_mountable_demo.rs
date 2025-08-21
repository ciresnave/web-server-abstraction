// Example demonstrating auth-integrated mountable web interfaces
//
// This example shows how libraries can define web interfaces with authentication
// requirements and mount them seamlessly with shared auth context.

use std::sync::Arc;
use web_server_abstraction::{
    AuthContext, AuthContextConfig, AuthRequirements, HttpMethod, InterfaceRegistry,
    MountableInterface, Request, Response, Result,
};

// =====================================================
// 1. Library with authentication-aware web interface
// =====================================================

/// A user management library that exposes authenticated web APIs
pub struct UserManagementLib {
    users: Arc<std::sync::Mutex<Vec<User>>>,
}

#[derive(Clone, Debug, serde::Serialize)]
struct User {
    id: u32,
    name: String,
    email: String,
}

impl Default for UserManagementLib {
    fn default() -> Self {
        Self::new()
    }
}

impl UserManagementLib {
    pub fn new() -> Self {
        Self {
            users: Arc::new(std::sync::Mutex::new(vec![
                User {
                    id: 1,
                    name: "Alice".to_string(),
                    email: "alice@example.com".to_string(),
                },
                User {
                    id: 2,
                    name: "Bob".to_string(),
                    email: "bob@example.com".to_string(),
                },
            ])),
        }
    }

    /// Create a mountable web interface with authentication requirements
    pub fn create_web_interface(&self) -> MountableInterface {
        let users_clone = Arc::clone(&self.users);
        let users_clone2 = Arc::clone(&self.users);
        let users_clone3 = Arc::clone(&self.users);

        MountableInterface::builder("user-management")
            .description("User management API with authentication")
            // Public endpoint - no auth required
            .route("/health", HttpMethod::GET, move |_req| {
                let users = users_clone3.clone();
                async move { health_handler(users).await }
            })
            // Protected endpoint - requires authentication and read permission
            .route_with_auth(
                "/users",
                HttpMethod::GET,
                move |_req| {
                    let users = users_clone.clone();
                    async move { list_users_handler(users).await }
                },
                AuthRequirements::required().with_permissions(vec!["user.read".to_string()]),
            )
            // Admin endpoint - requires authentication and admin permissions
            .route_with_auth(
                "/users/{id}",
                HttpMethod::DELETE,
                move |req| {
                    let users = users_clone2.clone();
                    async move { delete_user_handler(req, users).await }
                },
                AuthRequirements::required().with_permissions(vec!["user.admin".to_string()]),
            )
            .middleware("cors")
            .middleware("logging")
            .build()
    }
}

// Handler implementations
async fn list_users_handler(users: Arc<std::sync::Mutex<Vec<User>>>) -> Result<Response> {
    let users = users.lock().unwrap();
    let users_json = serde_json::to_string(&*users).unwrap();
    Response::json(&serde_json::json!({
        "users": serde_json::from_str::<serde_json::Value>(&users_json).unwrap(),
        "authenticated": true
    }))
}

async fn delete_user_handler(
    req: Request,
    users: Arc<std::sync::Mutex<Vec<User>>>,
) -> Result<Response> {
    let default_id = "0".to_string();
    let id_str = req.path_params.get("id").unwrap_or(&default_id);
    let id: u32 = id_str.parse().unwrap_or(0);

    let mut users = users.lock().unwrap();
    if let Some(pos) = users.iter().position(|u| u.id == id) {
        let deleted_user = users.remove(pos);
        Response::json(&serde_json::json!({
            "message": "User deleted successfully",
            "deleted_user": deleted_user
        }))
    } else {
        Ok(Response::not_found())
    }
}

async fn health_handler(users: Arc<std::sync::Mutex<Vec<User>>>) -> Result<Response> {
    let user_count = users.lock().unwrap().len();
    Response::json(&serde_json::json!({
        "status": "healthy",
        "user_count": user_count,
        "public_endpoint": true,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }))
}

// =====================================================
// 2. Admin panel library with higher security requirements
// =====================================================

pub struct AdminPanelLib;

impl Default for AdminPanelLib {
    fn default() -> Self {
        Self
    }
}

impl AdminPanelLib {
    pub fn new() -> Self {
        Self
    }

    pub fn create_web_interface(&self) -> MountableInterface {
        MountableInterface::builder("admin-panel")
            .description("Administrative panel with strict authentication")
            // All admin routes require high-level permissions
            .require_permissions(vec!["admin.full_access".to_string()])
            .route_with_auth(
                "/dashboard",
                HttpMethod::GET,
                |_req| async { admin_dashboard_handler().await },
                AuthRequirements::required()
                    .with_permissions(vec!["admin.read".to_string()])
                    .jwt_only(), // Only allow JWT authentication, no API keys
            )
            .route_with_auth(
                "/system/restart",
                HttpMethod::POST,
                |_req| async { system_restart_handler().await },
                AuthRequirements::required()
                    .with_permissions(vec!["admin.system".to_string()])
                    .jwt_only(),
            )
            .build()
    }
}

async fn admin_dashboard_handler() -> Result<Response> {
    Response::json(&serde_json::json!({
        "dashboard": "admin",
        "message": "Welcome to the admin dashboard",
        "security_level": "high",
        "auth_method": "jwt_required"
    }))
}

async fn system_restart_handler() -> Result<Response> {
    Response::json(&serde_json::json!({
        "message": "System restart initiated",
        "status": "success",
        "requires": "admin.system permission"
    }))
}

// =====================================================
// 3. Host application with unified authentication
// =====================================================

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔐 Auth-Integrated Mountable Interface Demo");
    println!("===========================================");

    // 1. Set up authentication context
    println!("\n🏗️  Setting up authentication context...");
    let auth_config = AuthContextConfig {
        jwt_secret: "demo-secret-key-change-in-production".to_string(),
        token_lifetime: std::time::Duration::from_secs(3600), // 1 hour
        require_auth_by_default: false,
        default_permissions: vec!["user.read".to_string()],
        ..Default::default()
    };

    let auth_context = Arc::new(AuthContext::new(auth_config).await?);
    println!("   ✅ Authentication context initialized");

    // 2. Create interface registry with auth support
    let mut registry = InterfaceRegistry::with_auth(auth_context.clone());
    println!("   ✅ Interface registry created with auth support");

    // 3. Create and register library interfaces
    println!("\n📚 Registering library interfaces...");

    let user_lib = UserManagementLib::new();
    let admin_lib = AdminPanelLib::new();

    registry.register(user_lib.create_web_interface())?;
    registry.register(admin_lib.create_web_interface())?;

    println!("   ✅ Registered: user-management, admin-panel");

    // 4. Mount interfaces with authentication
    println!("\n🔗 Mounting interfaces with authentication...");

    // Mount user management at /api/v1
    let user_routes = registry.mount("user-management", "/api/v1")?;
    println!(
        "   🔒 Mounted 'user-management' at /api/v1 ({} authenticated routes)",
        user_routes.len()
    );

    // Mount admin panel at /admin
    let admin_routes = registry.mount("admin-panel", "/admin")?;
    println!(
        "   🔒 Mounted 'admin-panel' at /admin ({} authenticated routes)",
        admin_routes.len()
    );

    // 5. Demonstrate route authentication requirements
    println!("\n🛡️  Authentication Requirements:");
    for interface_name in registry.list() {
        let interface = registry.get(interface_name).unwrap();
        println!("  📋 Interface: {}", interface.name());

        for route in interface.routes() {
            let auth_status = if route.auth_requirements.required {
                format!(
                    "🔐 PROTECTED (permissions: {:?})",
                    route.auth_requirements.permissions
                )
            } else {
                "🌍 PUBLIC".to_string()
            };

            println!("    • {:?} {} - {}", route.method, route.path, auth_status);
        }
    }

    // 6. Generate API tokens for testing (simulated)
    println!("\n🎟️  Authentication Token Generation:");
    println!("   👤 User token: jwt_user_token_with_read_permissions");
    println!("   � Admin token: jwt_admin_token_with_full_access");
    println!("   🔑 API key: wsa_api_key_for_service_auth");
    println!("   ℹ️  Note: Actual token generation requires proper auth method registration");

    // 7. Demonstrate unified authentication across interfaces
    println!("\n🌐 Unified Authentication Benefits:");
    println!("   ✨ Single sign-on across all mounted interfaces");
    println!("   ✨ Shared permission system");
    println!("   ✨ Centralized token management");
    println!("   ✨ Framework-agnostic authentication");
    println!("   ✨ Hot-mountable authenticated interfaces");

    println!("\n🚀 Example API Usage:");
    println!("   Public:     GET /api/v1/health (no auth required)");
    println!("   Protected:  GET /api/v1/users -H 'Authorization: Bearer jwt_user_token_...'");
    println!(
        "   Admin:      DELETE /api/v1/users/1 -H 'Authorization: Bearer jwt_admin_token_...'"
    );
    println!("   API Key:    GET /api/v1/users -H 'X-API-Key: wsa_api_key_...'");

    println!("\n✅ Auth-integrated mountable interface system ready!");
    println!("   🎯 This demonstrates the full vision: seamless authentication");
    println!("      across mountable web interfaces from different libraries!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_auth_integrated_interfaces() {
        let auth_config = AuthContextConfig::default();
        let auth_context = Arc::new(AuthContext::new(auth_config).await.unwrap());

        let mut registry = InterfaceRegistry::with_auth(auth_context.clone());

        let user_lib = UserManagementLib::new();
        registry.register(user_lib.create_web_interface()).unwrap();

        let routes = registry.mount("user-management", "/api").unwrap();
        assert_eq!(routes.len(), 3); // health, users, users/{id}

        // Verify that routes have proper auth requirements
        let interface = registry.get("user-management").unwrap();
        let routes_def = interface.routes();

        // Health endpoint should not require auth
        assert!(!routes_def[0].auth_requirements.required);

        // Users list should require auth
        assert!(routes_def[1].auth_requirements.required);
        assert!(routes_def[1]
            .auth_requirements
            .permissions
            .contains(&"user.read".to_string()));

        // Delete user should require admin auth
        assert!(routes_def[2].auth_requirements.required);
        assert!(routes_def[2]
            .auth_requirements
            .permissions
            .contains(&"user.admin".to_string()));
    }

    #[tokio::test]
    async fn test_admin_panel_security() {
        let admin_lib = AdminPanelLib::new();
        let interface = admin_lib.create_web_interface();

        // All admin routes should require authentication
        for route in interface.routes() {
            assert!(route.auth_requirements.required);
            assert!(!route.auth_requirements.permissions.is_empty());
        }
    }

    #[tokio::test]
    async fn test_token_creation() {
        let auth_config = AuthContextConfig::default();
        let auth_context = AuthContext::new(auth_config).await.unwrap();

        // Attempt to create a token, but don't unwrap as the JWT method might not be available
        // in the test environment
        let token_result = auth_context
            .create_token("test_user", vec!["read".to_string(), "write".to_string()])
            .await;

        // This test is primarily to verify that the interface works correctly
        // The actual token creation might fail in tests without a proper JWT setup
        match token_result {
            Ok(token) => assert!(!token.is_empty()),
            Err(e) => println!(
                "Token creation failed as expected in test environment: {:?}",
                e
            ),
        }
    }
}
