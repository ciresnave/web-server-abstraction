//! Comprehensive example demonstrating all implemented features.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use web_server_abstraction::{
    CompressionMiddleware, Config, ContentNegotiationMiddleware, Cookie, CspMiddleware,
    CsrfMiddleware, DatabaseValue, HttpMethod, Request, Response, Row, SessionManager, SharedState,
    StaticFileConfig, StaticFileHandler, WebServer, WebServerError, XssProtectionMiddleware,
    config::CompressionConfig, sanitize,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create static files first
    create_static_files()?;

    // 1. Configuration Management
    let config = Config::from_env();
    println!("Server running in {:?} mode", config.environment);
    println!("Binding to {}", config.bind_address());

    // 2. Shared State Management
    let _app_state = SharedState::new("Application State".to_string());
    let user_count = SharedState::new(0u64);

    // 3. Database Setup (Mock for example)
    // Note: Since MockDatabase implementation is simplified in this example,
    // we'll create a simple mock with a hashmap instead
    let _database = Arc::new(std::sync::Mutex::new(HashMap::<String, Vec<Row>>::new()));
    // Create sample user data - simplified for the example
    let mut users = Vec::new();
    let mut user_row = Row::new();
    user_row.set("id".to_string(), DatabaseValue::Integer(1));
    user_row.set(
        "username".to_string(),
        DatabaseValue::Text("john_doe".to_string()),
    );
    user_row.set(
        "email".to_string(),
        DatabaseValue::Text("john@example.com".to_string()),
    );
    user_row.set("active".to_string(), DatabaseValue::Integer(1));
    users.push(user_row);

    // 4. Session Management
    let session_manager = Arc::new(
        SessionManager::memory()
            .cookie_name("app_session".to_string())
            .duration(Duration::from_secs(24 * 60 * 60)) // 24 hours
            .secure(config.is_production())
            .http_only(true),
    );

    // 5. Static File Serving
    let static_files = StaticFileHandler::new(StaticFileConfig {
        root_dir: PathBuf::from("./static"),
        url_prefix: "/static".to_string(),
        show_index: true,
        cache: true,
        cache_max_age: 3600,
        ..Default::default()
    });

    // 6. Security Middleware
    let csrf_middleware = CsrfMiddleware::new(
        config
            .secret_key
            .clone()
            .unwrap_or_else(|| "default_secret".to_string()),
    )
    .exclude_path("/api/public".to_string())
    .token_lifetime(Duration::from_secs(3600));

    let xss_middleware = XssProtectionMiddleware::new()
        .filtering(true)
        .block_mode(true);

    let csp_middleware = CspMiddleware::default_policy().report_only(false);

    // 7. Content Negotiation
    let content_negotiation = ContentNegotiationMiddleware::new()
        .support_type("application/json".to_string(), 1.0)
        .support_type("text/html".to_string(), 0.9)
        .support_type("application/xml".to_string(), 0.8)
        .default_type("application/json".to_string());

    let compression = CompressionMiddleware::new(CompressionConfig {
        min_size: 1024,
        ..Default::default()
    });

    // Clone for use in closures
    let users_clone = Arc::new(users);
    let session_manager_clone = session_manager.clone();
    let user_count_clone = user_count.clone();

    // 8. Build Web Server with All Features
    let server = WebServer::new()
        // Home page with session demo
        .route("/", HttpMethod::GET, move |request: Request| {
            let session_manager = session_manager_clone.clone();
            let user_count = user_count_clone.clone();

            async move {
                // Get or create session
                // Note: The API has changed from the original example
                // In a real implementation, we'd use the SessionExt trait
                // Since cookie_name is private, we'll use a hardcoded name that should match
                let _session_id = request.cookie("app_session")
                    .map(|c| c.value.clone())
                    .unwrap_or_else(|| {
                        // Create new session
                        let session = session_manager.create_session();
                        session.id
                    });

                let session_data = session_manager.get_session(&request)
                    .unwrap_or_else(|| session_manager.create_session());

                // For this example, we'll manually track visits
                let visits = match session_data.data.get("visits") {
                    Some(visits_str) => visits_str.parse::<u32>().unwrap_or(0) + 1,
                    None => 1
                };

                // Create a mutable session for modification
                let mut updated_session = session_data.clone();
                updated_session.data.insert("visits".to_string(), visits.to_string());

                // Update global user count
                {
                    let mut count = user_count.write();
                    *count += 1;
                }

                let html = format!(r#"
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Web Server Abstraction Demo</title>
                        <link rel="stylesheet" href="/static/style.css">
                    </head>
                    <body>
                        <h1>Welcome to Web Server Abstraction Demo!</h1>
                        <p>Your visit count: {}</p>
                        <p>Total visits: {}</p>
                        <h2>Features Demonstrated:</h2>
                        <ul>
                            <li>✅ Session Management</li>
                            <li>✅ Shared State</li>
                            <li>✅ Static File Serving</li>
                            <li>✅ Cookie Support</li>
                            <li>✅ Content Negotiation</li>
                            <li>✅ Security Headers</li>
                            <li>✅ CSRF Protection</li>
                            <li>✅ Database Integration</li>
                            <li>✅ Form Handling</li>
                            <li>✅ File Uploads</li>
                        </ul>
                        <h2>API Endpoints:</h2>
                        <ul>
                            <li><a href="/api/users">GET /api/users</a> - List users</li>
                            <li><a href="/api/health">GET /api/health</a> - Health check</li>
                            <li><a href="/upload">GET /upload</a> - File upload form</li>
                        </ul>
                        <form action="/api/contact" method="POST">
                            <h3>Contact Form (CSRF Protected):</h3>
                            <input type="hidden" name="csrf_token" value="{{csrf_token}}">
                            <input type="text" name="name" placeholder="Your name" required><br>
                            <input type="email" name="email" placeholder="Your email" required><br>
                            <textarea name="message" placeholder="Your message" required></textarea><br>
                            <button type="submit">Send Message</button>
                        </form>
                    </body>
                    </html>
                "#, visits, user_count.read());

                let mut response = Response::ok()
                    .header("Content-Type", "text/html; charset=utf-8")
                    .body(html);

                // Save session
                response = session_manager.save_session(updated_session, response);

                Ok(response)
            }
        })

        // API endpoint with database integration
        .route("/api/users", HttpMethod::GET, move |_request| {
            let users = users_clone.clone();

            async move {
                // Instead of querying a database, we'll use our in-memory users vector
                let user_list: Vec<serde_json::Value> = users.iter().map(|row| {
                    serde_json::json!({
                        "id": match row.get("id") {
                            Some(DatabaseValue::Integer(id)) => *id,
                            _ => 0
                        },
                        "username": match row.get("username") {
                            Some(DatabaseValue::Text(name)) => name,
                            _ => ""
                        },
                        "email": match row.get("email") {
                            Some(DatabaseValue::Text(email)) => email,
                            _ => ""
                        },
                        "active": match row.get("active") {
                            Some(DatabaseValue::Integer(active)) => *active == 1,
                            _ => false
                        }
                    })
                }).collect();

                Response::json(&serde_json::json!({
                    "users": user_list,
                    "total": users.len()
                }))
            }
        })

        // Health check endpoint
        .route("/api/health", HttpMethod::GET, |_request| async {
            Response::json(&serde_json::json!({
                "status": "healthy",
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                "features": [
                    "sessions",
                    "static_files",
                    "csrf_protection",
                    "content_negotiation",
                    "compression",
                    "database",
                    "security_headers"
                ]
            }))
        })

        // File upload form
        .route("/upload", HttpMethod::GET, |_request| async {
            let html = r#"
                <!DOCTYPE html>
                <html>
                <head><title>File Upload</title></head>
                <body>
                    <h1>File Upload Demo</h1>
                    <form action="/api/upload" method="POST" enctype="multipart/form-data">
                        <input type="file" name="file" required><br>
                        <input type="text" name="description" placeholder="File description"><br>
                        <button type="submit">Upload File</button>
                    </form>
                </body>
                </html>
            "#;

            Ok(Response::ok()
                .header("Content-Type", "text/html; charset=utf-8")
                .body(html))
        })

        // File upload handler
        .route("/api/upload", HttpMethod::POST, |mut request: Request| async move {
            // Parse multipart form data
            request.parse_multipart().await.map_err(|e|
                WebServerError::custom(format!("Multipart parsing failed: {}", e))
            )?;

            let response = if let Some(multipart) = request.multipart() {
                // Simplified version without trying to extract files
                serde_json::json!({
                    "success": true,
                    "message": "File upload API is available but simplified in this demo",
                    "fields": multipart.fields.keys().collect::<Vec<_>>()
                })
            } else {
                serde_json::json!({
                    "success": false,
                    "error": "Invalid multipart data"
                })
            };

            Response::json(&response)
        })

        // Contact form handler (demonstrates CSRF protection)
        .route("/api/contact", HttpMethod::POST, |mut request: Request| async move {
            // Parse form data
            request.parse_form().await.map_err(|e|
                WebServerError::custom(format!("Form parsing failed: {}", e))
            )?;

            // Simplified form handling without try_get
            let name = request.form("name").unwrap_or("");
            let email = request.form("email").unwrap_or("");
            let message = request.form("message").unwrap_or("");

            let sanitized_name = sanitize::html(name);
            let sanitized_message = sanitize::html(message);

            // Validate email
            if !sanitize::is_valid_email(email) {
                return Response::json(&serde_json::json!({
                    "success": false,
                    "error": "Invalid email address"
                }));
            }

            // In a real application, you'd save to database and send email
            Response::json(&serde_json::json!({
                "success": true,
                "message": "Contact form submitted successfully",
                "data": {
                    "name": sanitized_name,
                    "email": email,
                    "message": sanitized_message
                }
            }))
        })

        // Demonstrate cookie handling
        .route("/api/set-preference", HttpMethod::POST, |_request| async {
            let preference_cookie = Cookie::new("user_preference", "dark_mode")
                .path("/")
                .max_age(Duration::from_secs(30 * 24 * 60 * 60)) // 30 days
                .http_only(false) // Allow JavaScript access for this example
                .secure(false); // Would be true in production with HTTPS

            Ok(Response::json(&serde_json::json!({
                "success": true,
                "message": "Preference saved"
            }))?.cookie(preference_cookie))
        })

        // Static file handler
        .route("/static/*path", HttpMethod::GET, move |request| {
            let static_handler = static_files.clone();
            async move {
                static_handler.handle(request).await
            }
        });

    // Apply middleware (order matters!)
    // Security middleware first
    let server = server
        .middleware(csrf_middleware)
        .middleware(xss_middleware)
        .middleware(csp_middleware)
        .middleware(content_negotiation)
        .middleware(compression);

    println!("🚀 Server starting with all features enabled!");
    println!("📝 Configuration: {:?}", config.environment);
    println!("🔒 Security: CSRF, XSS Protection, CSP enabled");
    println!("📁 Static files served from: ./static");
    println!("🗄️  Database: Mock database with sample data");
    println!("🍪 Sessions: Memory-based session storage");
    println!("🗜️  Compression: Enabled for responses > 1KB");
    println!("🌐 Content negotiation: JSON, HTML, XML support");
    println!("📊 Visit http://{} to see the demo", config.bind_address());

    // Bind and run server
    let server = server.bind(&config.bind_address()).await?;
    server.run().await?;

    Ok(())
}

// Create static CSS file for demo
// Create static CSS file for demo
fn create_static_files() -> std::io::Result<()> {
    std::fs::create_dir_all("./static")?;

    let css_content = r#"
body {
    font-family: Arial, sans-serif;
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
    line-height: 1.6;
}

h1, h2, h3 {
    color: #333;
}

ul {
    list-style-type: none;
    padding: 0;
}

li {
    background: #f4f4f4;
    margin: 5px 0;
    padding: 10px;
    border-left: 5px solid #007bff;
}

form {
    background: #f9f9f9;
    padding: 20px;
    border-radius: 5px;
    margin: 20px 0;
}

input, textarea, button {
    width: 100%;
    padding: 10px;
    margin: 5px 0;
    border: 1px solid #ddd;
    border-radius: 3px;
}

button {
    background: #007bff;
    color: white;
    border: none;
    cursor: pointer;
}

button:hover {
    background: #0056b3;
}

a {
    color: #007bff;
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}
"#;

    std::fs::write("./static/style.css", css_content)?;
    println!("Created ./static/style.css");

    Ok(())
}
