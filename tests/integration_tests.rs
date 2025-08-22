use web_server_abstraction::{
    middleware::{AuthMiddleware, CorsMiddleware, LoggingMiddleware},
    types::{HttpMethod, Response, StatusCode},
    WebServer,
};

#[tokio::test]
async fn test_basic_server_creation() {
    let server = WebServer::new().route("/test", HttpMethod::GET, |_req| async {
        Ok(Response::ok().body("Test response"))
    });

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();

    // In a real test, you'd make HTTP requests to verify functionality
    // For now, we just verify the server can be created and bound
}

#[tokio::test]
async fn test_middleware_integration() {
    let server = WebServer::new().middleware(LoggingMiddleware::new()).route(
        "/",
        HttpMethod::GET,
        |_req| async { Ok(Response::ok().body("Hello")) },
    );

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[tokio::test]
async fn test_multiple_routes() {
    let server = WebServer::new()
        .route("/users", HttpMethod::GET, |_req| async {
            Ok(Response::ok().body("Users list"))
        })
        .route("/users", HttpMethod::POST, |_req| async {
            Ok(Response::new(StatusCode::CREATED).body("User created"))
        })
        .route("/health", HttpMethod::GET, |_req| async {
            Ok(Response::ok().body("OK"))
        });

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[tokio::test]
async fn test_all_http_methods() {
    let server = WebServer::new()
        .get("/get", |_req| async {
            Ok(Response::ok().body("GET response"))
        })
        .post("/post", |_req| async {
            Ok(Response::ok().body("POST response"))
        })
        .put("/put", |_req| async {
            Ok(Response::ok().body("PUT response"))
        })
        .delete("/delete", |_req| async {
            Ok(Response::ok().body("DELETE response"))
        })
        .patch("/patch", |_req| async {
            Ok(Response::ok().body("PATCH response"))
        })
        .head("/head", |_req| async { Ok(Response::ok()) }) // HEAD returns no body
        .options("/options", |_req| async {
            Ok(Response::ok()
                .header("Allow", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS")
                .body("OPTIONS response"))
        })
        .trace("/trace", |_req| async {
            Ok(Response::ok().body("TRACE response"))
        })
        .connect("/connect", |_req| async {
            Ok(Response::ok().body("CONNECT response"))
        });

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[tokio::test]
async fn test_path_parameter_extraction() {
    let server = WebServer::new()
        .route("/users/:id", HttpMethod::GET, |_req| async {
            // In a real implementation, we would extract the ID from req.param("id")
            Ok(Response::ok().body("User found"))
        })
        .route(
            "/users/:user_id/posts/:post_id",
            HttpMethod::GET,
            |_req| async {
                // In a real implementation, we would extract both parameters
                Ok(Response::ok().body("User post found"))
            },
        )
        .with_path_params(); // Enable automatic parameter extraction

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[tokio::test]
async fn test_json_handling() {
    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestData {
        message: String,
    }

    let server = WebServer::new().route("/json", HttpMethod::POST, |_req| async {
        // In a real implementation, we would parse JSON from req.json()
        let response_data = TestData {
            message: "success".to_string(),
        };
        Response::json(&response_data)
    });

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[tokio::test]
async fn test_error_handling() {
    use web_server_abstraction::error::WebServerError;

    let server = WebServer::new()
        .route("/error", HttpMethod::GET, |_req| async {
            Err(WebServerError::Custom("Test error".to_string()))
        })
        .route("/not-found", HttpMethod::GET, |_req| async {
            Ok(Response::new(StatusCode::NOT_FOUND).body("Not found"))
        });

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[tokio::test]
async fn test_websocket_routes() {
    let server = WebServer::new().websocket("/ws").websocket("/chat").route(
        "/api/test",
        HttpMethod::GET,
        |_req| async { Ok(Response::ok().body("API response")) },
    );

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[tokio::test]
async fn test_wildcard_routes() {
    let server = WebServer::new()
        .route("/static/*file", HttpMethod::GET, |_req| async {
            Ok(Response::ok()
                .header("Content-Type", "application/octet-stream")
                .body("Static file content"))
        })
        .route("/assets/*path", HttpMethod::GET, |_req| async {
            Ok(Response::ok().body("Asset content"))
        })
        .with_path_params();

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[tokio::test]
async fn test_middleware_chain() {
    let server = WebServer::new()
        .middleware(LoggingMiddleware::new())
        .middleware(CorsMiddleware::new().allow_origin("*"))
        .middleware(AuthMiddleware::new().with_bearer_tokens(vec!["test-token".to_string()]))
        .route("/protected", HttpMethod::GET, |_req| async {
            Ok(Response::ok().body("Protected content"))
        });

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[tokio::test]
async fn test_header_manipulation() {
    let server = WebServer::new().route("/headers", HttpMethod::GET, |_req| async {
        Ok(Response::ok()
            .header("X-Custom-Header", "test-value")
            .header("Cache-Control", "no-cache")
            .body("Headers set"))
    });

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[tokio::test]
async fn test_status_codes() {
    let server = WebServer::new()
        .route("/ok", HttpMethod::GET, |_req| async {
            Ok(Response::ok().body("200 OK"))
        })
        .route("/created", HttpMethod::POST, |_req| async {
            Ok(Response::new(StatusCode::CREATED).body("201 Created"))
        })
        .route("/custom", HttpMethod::GET, |_req| async {
            Ok(Response::new(StatusCode(418)).body("418 I'm a teapot"))
        });

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

// Framework-specific adapter tests
#[cfg(feature = "rocket")]
#[tokio::test]
async fn test_rocket_adapter() {
    use web_server_abstraction::{core::AdapterType, RocketAdapter};

    let server = WebServer::new()
        .route("/rocket", HttpMethod::GET, |_req| async {
            Ok(Response::ok().body("Rocket adapter working"))
        })
        .adapter(AdapterType::Rocket);

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[cfg(feature = "salvo")]
#[tokio::test]
async fn test_salvo_adapter() {
    use web_server_abstraction::{core::AdapterType, SalvoAdapter};

    let server = WebServer::new()
        .route("/salvo", HttpMethod::GET, |_req| async {
            Ok(Response::ok().body("Salvo adapter working"))
        })
        .adapter(AdapterType::Salvo);

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[cfg(feature = "poem")]
#[tokio::test]
async fn test_poem_adapter() {
    use web_server_abstraction::{core::AdapterType, PoemAdapter};

    let server = WebServer::new()
        .route("/poem", HttpMethod::GET, |_req| async {
            Ok(Response::ok().body("Poem adapter working"))
        })
        .adapter(AdapterType::Poem);

    let _bound_server = server.bind("127.0.0.1:0").await.unwrap();
}

#[cfg(any(feature = "rocket", feature = "salvo", feature = "poem"))]
#[tokio::test]
async fn test_multiple_framework_adapters() {
    // Test that we can create servers with different adapters
    let mock_server = WebServer::new().route("/mock", HttpMethod::GET, |_req| async {
        Ok(Response::ok().body("Mock adapter"))
    });

    #[cfg(feature = "rocket")]
    {
        use web_server_abstraction::core::AdapterType;
        let rocket_server = WebServer::new()
            .route("/rocket", HttpMethod::GET, |_req| async {
                Ok(Response::ok().body("Rocket adapter"))
            })
            .adapter(AdapterType::Rocket);
        let _rocket_bound = rocket_server.bind("127.0.0.1:0").await.unwrap();
    }

    #[cfg(feature = "salvo")]
    {
        use web_server_abstraction::core::AdapterType;
        let salvo_server = WebServer::new()
            .route("/salvo", HttpMethod::GET, |_req| async {
                Ok(Response::ok().body("Salvo adapter"))
            })
            .adapter(AdapterType::Salvo);
        let _salvo_bound = salvo_server.bind("127.0.0.1:0").await.unwrap();
    }

    #[cfg(feature = "poem")]
    {
        use web_server_abstraction::core::AdapterType;
        let poem_server = WebServer::new()
            .route("/poem", HttpMethod::GET, |_req| async {
                Ok(Response::ok().body("Poem adapter"))
            })
            .adapter(AdapterType::Poem);
        let _poem_bound = poem_server.bind("127.0.0.1:0").await.unwrap();
    }

    let _mock_bound = mock_server.bind("127.0.0.1:0").await.unwrap();
}
