// Example demonstrating mountable web interfaces for library integration
//
// This example shows how libraries can define web interfaces that can be
// mounted into any host application without tying them to a specific web framework.
// This enables "composable web applications" from multiple libraries.

use std::sync::Arc;
use web_server_abstraction::{
    AuthContext, AuthContextConfig, AuthRequirements, HttpMethod, InterfaceRegistry,
    MountableInterface, Request, Response, Result,
};

// =====================================================
// 1. Library-side code: Define a mountable interface
// =====================================================

/// A hypothetical user management library that exposes web APIs
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

    /// Create a mountable web interface for this library
    /// This is the key method - libraries expose their web APIs this way
    pub fn create_web_interface(&self) -> MountableInterface {
        let users_clone = Arc::clone(&self.users);
        let users_clone2 = Arc::clone(&self.users);
        let users_clone3 = Arc::clone(&self.users);

        MountableInterface::builder("user-management")
            .description("User management API")
            .route("/users", HttpMethod::GET, move |_req| {
                let users = users_clone.clone();
                async move { list_users_handler(users).await }
            })
            .route_with_auth(
                "/users/{id}",
                HttpMethod::GET,
                move |req| {
                    let users = users_clone2.clone();
                    async move { get_user_handler(req, users).await }
                },
                AuthRequirements::required().with_permissions(vec!["users.read".to_string()]),
            )
            .route("/health", HttpMethod::GET, move |_req| {
                let users = users_clone3.clone();
                async move { health_handler(users).await }
            })
            .middleware("cors")
            .middleware("logging")
            .build()
    }
}

// Handler implementations for the library
async fn list_users_handler(users: Arc<std::sync::Mutex<Vec<User>>>) -> Result<Response> {
    let users = users.lock().unwrap();
    let users_json = serde_json::to_string(&*users).unwrap();
    Response::json(&serde_json::json!({
        "users": serde_json::from_str::<serde_json::Value>(&users_json).unwrap()
    }))
}

async fn get_user_handler(
    req: Request,
    users: Arc<std::sync::Mutex<Vec<User>>>,
) -> Result<Response> {
    let default_id = "0".to_string();
    let id_str = req.path_params.get("id").unwrap_or(&default_id);
    let id: u32 = id_str.parse().unwrap_or(0);

    let users = users.lock().unwrap();
    if let Some(user) = users.iter().find(|u| u.id == id) {
        Ok(Response::json(user)?)
    } else {
        Ok(Response::not_found())
    }
}

async fn health_handler(users: Arc<std::sync::Mutex<Vec<User>>>) -> Result<Response> {
    let user_count = users.lock().unwrap().len();
    Response::json(&serde_json::json!({
        "status": "healthy",
        "user_count": user_count,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }))
}

// =====================================================
// 2. Another library with its own web interface
// =====================================================

pub struct NotificationLib {
    notifications: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Default for NotificationLib {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationLib {
    pub fn new() -> Self {
        Self {
            notifications: Arc::new(std::sync::Mutex::new(vec![
                "Welcome to the system".to_string(),
                "Your profile is incomplete".to_string(),
            ])),
        }
    }

    pub fn create_web_interface(&self) -> MountableInterface {
        let notifications_clone = Arc::clone(&self.notifications);

        MountableInterface::builder("notifications")
            .description("Notification management API")
            .route_with_auth(
                "/notifications",
                HttpMethod::GET,
                move |_req| {
                    let notifications = notifications_clone.clone();
                    async move {
                        let notifications = notifications.lock().unwrap();
                        Response::json(&serde_json::json!({
                            "notifications": *notifications
                        }))
                    }
                },
                AuthRequirements::required()
                    .with_permissions(vec!["notifications.read".to_string()]),
            )
            .middleware("auth")
            .build()
    }
}

// =====================================================
// 3. Host application: Mount multiple interfaces
// =====================================================

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Mountable Interface Demo");
    println!("==========================");

    // Host application creates libraries
    let user_lib = UserManagementLib::new();
    let notification_lib = NotificationLib::new();

    // Initialize authentication context
    println!("\n🔒 Setting up Authentication");
    let auth_config = AuthContextConfig::default();
    let auth_context = AuthContext::new(auth_config).await?;
    println!("  • Authentication context initialized");

    // Create an interface registry with authentication support
    let mut registry = InterfaceRegistry::with_auth(Arc::new(auth_context));
    println!("  • Interface registry created with authentication support");

    // Register library interfaces
    registry.register(user_lib.create_web_interface())?;
    registry.register(notification_lib.create_web_interface())?;
    println!("  • Library interfaces registered");

    // List registered interfaces
    println!("\n📋 Registered Interfaces:");
    for interface_name in registry.list() {
        let interface = registry.get(interface_name).unwrap();
        println!("  • {} - {}", interface.name(), interface.description());
        println!("    Routes: {}", interface.routes().len());
        println!("    Middleware: {:?}", interface.middleware());
    }

    // Mount interfaces at different paths
    println!("\n🔗 Mounting Interfaces with Authentication:");

    // Mount user management at /api/v1/users
    let user_routes = registry.mount("user-management", "/api/v1")?;
    println!(
        "  • Mounted 'user-management' at /api/v1 ({} authenticated routes)",
        user_routes.len()
    );

    // Mount notifications at /api/v1/notifications
    let notification_routes = registry.mount("notifications", "/api/v1")?;
    println!(
        "  • Mounted 'notifications' at /api/v1 ({} authenticated routes)",
        notification_routes.len()
    );

    // Mount user management again at a different path (e.g., for admin interface)
    let admin_routes = registry.mount("user-management", "/admin")?;
    println!(
        "  • Mounted 'user-management' at /admin ({} authenticated routes)",
        admin_routes.len()
    );

    // Inspect authentication requirements for routes
    println!("\n🔐 Authentication Requirements:");
    for route in &user_routes {
        println!(
            "  • Route Authentication Required: {}",
            route.auth_requirements.required
        );

        if !route.auth_requirements.permissions.is_empty() {
            println!(
                "    Required Permissions: {:?}",
                route.auth_requirements.permissions
            );
        }
    }

    // Generate OpenAPI documentation
    println!("\n📖 OpenAPI Documentation:");
    for interface_name in registry.list() {
        let interface = registry.get(interface_name).unwrap();
        let spec = interface.openapi_spec();
        println!("  • {}:", spec.interface_name);
        for route_doc in &spec.routes {
            println!(
                "    - {:?} {} - {:?}",
                route_doc.method,
                route_doc.path,
                route_doc.description.as_deref().unwrap_or("No description")
            );
        }
    }

    // Demonstrate mounting all interfaces at once
    let all_routes = registry.mount_all()?;
    println!(
        "\n🌐 Total routes when mounting all interfaces: {}",
        all_routes.len()
    );

    println!("\n✅ Demo completed successfully!");
    println!("\n💡 Key Benefits:");
    println!("  • Libraries define web interfaces independently");
    println!("  • Host apps can mount interfaces at any path");
    println!("  • Same interface can be mounted multiple times");
    println!("  • Framework-agnostic - works with any web framework");
    println!("  • Automatic OpenAPI documentation generation");
    println!("  • Seamless authentication across all interfaces!");
    println!("  • Unified permission system across library boundaries!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn setup_auth_context() -> Result<AuthContext> {
        let config = AuthContextConfig {
            token_lifetime: Duration::from_secs(3600),
            ..Default::default()
        };
        AuthContext::new(config).await
    }

    #[tokio::test]
    async fn test_library_integration() {
        let user_lib = UserManagementLib::new();
        let interface = user_lib.create_web_interface();

        assert_eq!(interface.name(), "user-management");
        assert_eq!(interface.routes().len(), 3);

        // Test mounting with auth
        let auth_context = setup_auth_context().await.unwrap();
        let routes = interface
            .mount_with_auth_at("/api/v1", Arc::new(auth_context))
            .unwrap();
        assert_eq!(routes.len(), 3);
    }

    #[tokio::test]
    async fn test_multiple_libraries() {
        let auth_context = setup_auth_context().await.unwrap();
        let mut registry = InterfaceRegistry::with_auth(Arc::new(auth_context));

        let user_lib = UserManagementLib::new();
        let notification_lib = NotificationLib::new();

        registry.register(user_lib.create_web_interface()).unwrap();
        registry
            .register(notification_lib.create_web_interface())
            .unwrap();

        assert_eq!(registry.list().len(), 2);
        assert!(registry.get("user-management").is_some());
        assert!(registry.get("notifications").is_some());
    }

    #[tokio::test]
    async fn test_mounting_flexibility() {
        let auth_context = setup_auth_context().await.unwrap();
        let mut registry = InterfaceRegistry::with_auth(Arc::new(auth_context));

        let user_lib = UserManagementLib::new();
        registry.register(user_lib.create_web_interface()).unwrap();

        // Same interface can be mounted at different paths
        let api_routes = registry.mount("user-management", "/api/v1").unwrap();
        let admin_routes = registry.mount("user-management", "/admin").unwrap();
        let public_routes = registry.mount("user-management", "/public").unwrap();

        assert_eq!(api_routes.len(), 3);
        assert_eq!(admin_routes.len(), 3);
        assert_eq!(public_routes.len(), 3);
    }
}
