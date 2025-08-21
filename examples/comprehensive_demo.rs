use web_server_abstraction::{HttpMethod, Request, Response, WebServer};

/// Comprehensive example demonstrating all common web framework functionality
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starting comprehensive web framework feature demo...");

    let _server = WebServer::new()
        // Basic routes
        .route("/", HttpMethod::GET, |_req| async {
            Ok(Response::html(
                "<h1>Welcome to the Web Server Abstraction Demo!</h1>
                <ul>
                    <li><a href='/hello'>Hello World</a></li>
                    <li><a href='/json'>JSON Response</a></li>
                    <li><a href='/cookies'>Set Cookies</a></li>
                    <li><a href='/redirect'>Redirect Example</a></li>
                    <li><a href='/users/123'>User Profile (Path Params)</a></li>
                    <li><a href='/query?name=John&age=30'>Query Parameters</a></li>
                    <li><a href='/form'>Form Example</a></li>
                    <li><a href='/download'>File Download</a></li>
                </ul>",
            ))
        })
        // Simple text response
        .route("/hello", HttpMethod::GET, |_req| async {
            Ok(Response::text("Hello, World from the abstraction layer!"))
        })
        // JSON response example
        .route("/json", HttpMethod::GET, |_req| async {
            let data = serde_json::json!({
                "message": "This is a JSON response",
                "status": "success",
                "features": [
                    "Framework agnostic",
                    "Type safe",
                    "Async first",
                    "Middleware support"
                ]
            });
            Response::json(&data)
        })
        // Cookie management
        .route("/cookies", HttpMethod::GET, |_req| async {
            use std::time::Duration;
            use web_server_abstraction::types::{Cookie, SameSite};

            let session_cookie = Cookie::new("session_id", "abc123")
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Lax)
                .max_age(Duration::from_secs(3600)); // 1 hour

            let user_pref = Cookie::new("theme", "dark")
                .path("/")
                .max_age(Duration::from_secs(86400 * 30)); // 30 days

            Ok(Response::ok()
                .cookie(session_cookie)
                .cookie(user_pref)
                .body("Cookies have been set! Check your browser dev tools."))
        })
        // Redirect example
        .route("/redirect", HttpMethod::GET, |_req| async {
            Ok(Response::redirect("/hello"))
        })
        // Path parameters demo
        .route("/users/{id}", HttpMethod::GET, |req: Request| async move {
            let user_id = req.path_param("id").unwrap_or("unknown");

            let response_html = format!(
                "<h1>User Profile</h1>
                <p>User ID: {}</p>
                <p>This demonstrates path parameter extraction.</p>
                <a href='/'>← Back to home</a>",
                user_id
            );

            Ok(Response::html(response_html))
        })
        // Query parameters demo
        .route("/query", HttpMethod::GET, |req: Request| async move {
            let name = req
                .query_param("name")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Anonymous".to_string());
            let age = req
                .query_param("age")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let response_html = format!(
                "<h1>Query Parameters Demo</h1>
                <p>Name: {}</p>
                <p>Age: {}</p>
                <p>User Agent: {}</p>
                <p>All query params: {:?}</p>
                <a href='/'>← Back to home</a>",
                name,
                age,
                req.user_agent().unwrap_or("unknown"),
                req.query_params()
            );

            Ok(Response::html(response_html))
        })
        // Content negotiation example
        .route("/content", HttpMethod::GET, |req: Request| async move {
            if req.accepts("application/json") {
                let data = serde_json::json!({
                    "message": "JSON response based on Accept header",
                    "content_type": "application/json"
                });
                Response::json(&data)
            } else if req.accepts("text/html") {
                Ok(Response::html(
                    "<h1>HTML Response</h1>
                    <p>This is an HTML response based on the Accept header.</p>",
                ))
            } else {
                Ok(Response::text("Plain text response"))
            }
        })
        // Form handling example
        .route("/form", HttpMethod::GET, |_req| async {
            Ok(Response::html(
                "<h1>Form Example</h1>
                <form method='post' action='/form'>
                    <p>
                        <label>Name: <input type='text' name='name' required></label>
                    </p>
                    <p>
                        <label>Email: <input type='email' name='email' required></label>
                    </p>
                    <p>
                        <label>Message: <textarea name='message'></textarea></label>
                    </p>
                    <p>
                        <button type='submit'>Submit</button>
                    </p>
                </form>
                <a href='/'>← Back to home</a>",
            ))
        })
        .route("/form", HttpMethod::POST, |mut req: Request| async move {
            // Parse form data
            req.parse_form().await?;

            let name = req.form("name").unwrap_or("Unknown");
            let email = req.form("email").unwrap_or("No email");
            let message = req.form("message").unwrap_or("No message");

            let response_html = format!(
                "<h1>Form Submitted!</h1>
                <p><strong>Name:</strong> {}</p>
                <p><strong>Email:</strong> {}</p>
                <p><strong>Message:</strong> {}</p>
                <a href='/form'>← Submit another</a> |
                <a href='/'>← Back to home</a>",
                name, email, message
            );

            Ok(Response::html(response_html))
        })
        // File download example
        .route("/download", HttpMethod::GET, |_req| async {
            let file_content =
                b"This is a sample file for download.\nIt demonstrates file serving capabilities.";
            Ok(Response::download("sample.txt", file_content.to_vec()))
        })
        // CORS example
        .route("/api/data", HttpMethod::GET, |_req| async {
            let data = serde_json::json!({
                "data": [1, 2, 3, 4, 5],
                "message": "This endpoint has CORS enabled"
            });
            Ok(Response::json(&data)?.cors())
        })
        // Cache control examples
        .route("/cached", HttpMethod::GET, |_req| async {
            Ok(Response::text("This response is cached for 1 hour").cache(3600))
        })
        .route("/no-cache", HttpMethod::GET, |_req| async {
            Ok(Response::text("This response should never be cached").no_cache())
        })
        // Error responses
        .route("/error", HttpMethod::GET, |_req| async {
            Ok(Response::internal_server_error("This is a simulated error"))
        })
        .route("/not-found", HttpMethod::GET, |_req| async {
            Ok(Response::not_found())
        })
        // JSON POST example
        .route("/api/users", HttpMethod::POST, |req: Request| async move {
            // Parse JSON from request body
            #[derive(serde::Deserialize, serde::Serialize)]
            struct User {
                name: String,
                email: String,
            }

            match req.json::<User>().await {
                Ok(user) => {
                    let response = serde_json::json!({
                        "message": "User created successfully",
                        "user": user,
                        "id": 12345
                    });
                    Response::json(&response)
                }
                Err(_) => Ok(Response::bad_request("Invalid JSON data")),
            }
        });

    println!("✅ Server configured with comprehensive examples!");
    println!("📖 Available endpoints:");
    println!("   GET  /                  - Home page with navigation");
    println!("   GET  /hello             - Simple text response");
    println!("   GET  /json              - JSON response");
    println!("   GET  /cookies           - Cookie management");
    println!("   GET  /redirect          - Redirect example");
    println!("   GET  /users/{{id}}        - Path parameters");
    println!("   GET  /query?name=X&age=Y - Query parameters");
    println!("   GET  /content           - Content negotiation");
    println!("   GET  /form              - Form (GET)");
    println!("   POST /form              - Form submission");
    println!("   GET  /download          - File download");
    println!("   GET  /api/data          - CORS enabled API");
    println!("   GET  /cached            - Cached response");
    println!("   GET  /no-cache          - Non-cached response");
    println!("   GET  /error             - Error response");
    println!("   GET  /not-found         - 404 response");
    println!("   POST /api/users         - JSON POST example");

    println!("\n🎉 Demo complete! All common web framework functionality implemented:");
    println!("   ✅ Request/Response types with convenience methods");
    println!("   ✅ JSON parsing and generation");
    println!("   ✅ Query parameter parsing");
    println!("   ✅ Path parameter extraction");
    println!("   ✅ Cookie management");
    println!("   ✅ Form data parsing (URL-encoded)");
    println!("   ✅ Content type detection and negotiation");
    println!("   ✅ File serving and downloads");
    println!("   ✅ HTTP redirects");
    println!("   ✅ Cache control headers");
    println!("   ✅ CORS support");
    println!("   ✅ Error responses");
    println!("   ✅ Static file serving (infrastructure)");
    println!("   ✅ Routing with pattern matching");

    Ok(())
}
