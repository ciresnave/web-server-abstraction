//! Unit tests for core routing and path parameter extraction

use super::*;
use crate::types::{HttpMethod, Request, Response, StatusCode};
use http::Uri;
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_creation() {
        let route = Route::new("/users/:id", HttpMethod::GET, |_req| async {
            Ok(Response::ok().body("test"))
        });

        assert_eq!(route.path, "/users/:id");
        assert_eq!(route.method, HttpMethod::GET);
    }

    #[test]
    fn test_route_matching_exact() {
        let route = Route::new("/users", HttpMethod::GET, |_req| async {
            Ok(Response::ok())
        });

        // Test exact matches
        assert!(route.matches("/users"));
        assert!(!route.matches("/users/123"));
        assert!(!route.matches("/"));
        assert!(!route.matches("/user"));
        assert!(!route.matches("/users/"));
    }

    #[test]
    fn test_route_matching_with_parameters() {
        let route = Route::new("/users/:id", HttpMethod::GET, |_req| async {
            Ok(Response::ok())
        });

        // Test parameter matches
        assert!(route.matches("/users/123"));
        assert!(route.matches("/users/abc"));
        assert!(route.matches("/users/user-123"));
        assert!(!route.matches("/users"));
        assert!(!route.matches("/users/"));
        assert!(!route.matches("/users/123/extra"));
    }

    #[test]
    fn test_route_matching_multiple_parameters() {
        let route = Route::new(
            "/users/:user_id/posts/:post_id",
            HttpMethod::GET,
            |_req| async { Ok(Response::ok()) },
        );

        // Test multiple parameter matches
        assert!(route.matches("/users/123/posts/456"));
        assert!(route.matches("/users/john/posts/hello-world"));
        assert!(!route.matches("/users/123"));
        assert!(!route.matches("/users/123/posts"));
        assert!(!route.matches("/users/123/posts/456/extra"));
    }

    #[test]
    fn test_route_matching_wildcard() {
        let route = Route::new("/static/*file", HttpMethod::GET, |_req| async {
            Ok(Response::ok())
        });

        // Test wildcard matches
        assert!(route.matches("/static/css/style.css"));
        assert!(route.matches("/static/js/app.js"));
        assert!(route.matches("/static/images/logo.png"));
        assert!(route.matches("/static/favicon.ico"));
        assert!(!route.matches("/static"));
        assert!(!route.matches("/assets/style.css"));
    }

    #[test]
    fn test_route_parameter_extraction() {
        let route = Route::new("/users/:id", HttpMethod::GET, |_req| async {
            Ok(Response::ok())
        });

        let params = route.extract_params("/users/123");
        assert_eq!(params.len(), 1);
        assert_eq!(params.get("id"), Some(&"123".to_string()));

        let params = route.extract_params("/users/john-doe");
        assert_eq!(params.get("id"), Some(&"john-doe".to_string()));
    }

    #[test]
    fn test_route_multiple_parameter_extraction() {
        let route = Route::new(
            "/users/:user_id/posts/:post_id",
            HttpMethod::GET,
            |_req| async { Ok(Response::ok()) },
        );

        let params = route.extract_params("/users/123/posts/456");
        assert_eq!(params.len(), 2);
        assert_eq!(params.get("user_id"), Some(&"123".to_string()));
        assert_eq!(params.get("post_id"), Some(&"456".to_string()));

        let params = route.extract_params("/users/john/posts/hello-world");
        assert_eq!(params.get("user_id"), Some(&"john".to_string()));
        assert_eq!(params.get("post_id"), Some(&"hello-world".to_string()));
    }

    #[test]
    fn test_route_wildcard_parameter_extraction() {
        let route = Route::new("/static/*file", HttpMethod::GET, |_req| async {
            Ok(Response::ok())
        });

        let params = route.extract_params("/static/css/style.css");
        assert_eq!(params.len(), 1);
        assert_eq!(params.get("file"), Some(&"css/style.css".to_string()));

        let params = route.extract_params("/static/images/subfolder/logo.png");
        assert_eq!(
            params.get("file"),
            Some(&"images/subfolder/logo.png".to_string())
        );
    }

    #[test]
    fn test_route_no_parameter_extraction_for_non_matching() {
        let route = Route::new("/users/:id", HttpMethod::GET, |_req| async {
            Ok(Response::ok())
        });

        let params = route.extract_params("/posts/123");
        assert!(params.is_empty());

        let params = route.extract_params("/users");
        assert!(params.is_empty());
    }

    #[test]
    fn test_route_complex_patterns() {
        // Test route with mixed literal and parameter segments
        let route = Route::new("/api/v1/users/:id/profile", HttpMethod::GET, |_req| async {
            Ok(Response::ok())
        });

        assert!(route.matches("/api/v1/users/123/profile"));
        assert!(!route.matches("/api/v2/users/123/profile"));
        assert!(!route.matches("/api/v1/posts/123/profile"));

        let params = route.extract_params("/api/v1/users/john-doe/profile");
        assert_eq!(params.get("id"), Some(&"john-doe".to_string()));
    }

    #[test]
    fn test_route_edge_cases() {
        // Test empty segments and special characters
        let route = Route::new("/users/:id", HttpMethod::GET, |_req| async {
            Ok(Response::ok())
        });

        // Test with URL encoded characters
        let params = route.extract_params("/users/user%40example.com");
        assert_eq!(params.get("id"), Some(&"user%40example.com".to_string()));

        // Test with hyphens and underscores
        let params = route.extract_params("/users/user-name_123");
        assert_eq!(params.get("id"), Some(&"user-name_123".to_string()));
    }

    #[test]
    fn test_web_server_route_registration() {
        let server = WebServer::new()
            .route("/test", HttpMethod::GET, |_req| async {
                Ok(Response::ok().body("test"))
            })
            .route("/users/:id", HttpMethod::GET, |_req| async {
                Ok(Response::ok().body("user"))
            });

        assert_eq!(server.routes.len(), 2);
        assert_eq!(server.routes[0].path, "/test");
        assert_eq!(server.routes[0].method, HttpMethod::GET);
        assert_eq!(server.routes[1].path, "/users/:id");
        assert_eq!(server.routes[1].method, HttpMethod::GET);
    }

    #[test]
    fn test_web_server_convenience_methods() {
        let server = WebServer::new()
            .get("/get", |_req| async { Ok(Response::ok()) })
            .post("/post", |_req| async { Ok(Response::ok()) })
            .put("/put", |_req| async { Ok(Response::ok()) })
            .delete("/delete", |_req| async { Ok(Response::ok()) })
            .patch("/patch", |_req| async { Ok(Response::ok()) })
            .head("/head", |_req| async { Ok(Response::ok()) })
            .options("/options", |_req| async { Ok(Response::ok()) })
            .trace("/trace", |_req| async { Ok(Response::ok()) })
            .connect("/connect", |_req| async { Ok(Response::ok()) });

        assert_eq!(server.routes.len(), 9);

        // Verify each route has the correct method
        assert_eq!(server.routes[0].method, HttpMethod::GET);
        assert_eq!(server.routes[1].method, HttpMethod::POST);
        assert_eq!(server.routes[2].method, HttpMethod::PUT);
        assert_eq!(server.routes[3].method, HttpMethod::DELETE);
        assert_eq!(server.routes[4].method, HttpMethod::PATCH);
        assert_eq!(server.routes[5].method, HttpMethod::HEAD);
        assert_eq!(server.routes[6].method, HttpMethod::OPTIONS);
        assert_eq!(server.routes[7].method, HttpMethod::TRACE);
        assert_eq!(server.routes[8].method, HttpMethod::CONNECT);
    }

    #[test]
    fn test_web_server_middleware_registration() {
        use crate::middleware::LoggingMiddleware;

        let server = WebServer::new().middleware(LoggingMiddleware::new()).route(
            "/test",
            HttpMethod::GET,
            |_req| async { Ok(Response::ok()) },
        );

        assert_eq!(server.middleware.len(), 1);
        assert_eq!(server.routes.len(), 1);
    }

    #[test]
    fn test_web_server_with_path_params() {
        let server = WebServer::new()
            .route("/users/:id", HttpMethod::GET, |_req| async {
                Ok(Response::ok())
            })
            .route("/posts/:post_id", HttpMethod::GET, |_req| async {
                Ok(Response::ok())
            })
            .with_path_params();

        // Should have added PathParameterMiddleware
        assert_eq!(server.middleware.len(), 1);
        assert_eq!(server.routes.len(), 2);
    }

    #[test]
    fn test_web_server_websocket_route() {
        let server = WebServer::new().websocket("/ws").websocket("/chat/:room");

        // WebSocket routes are added as regular routes with GET method
        assert_eq!(server.routes.len(), 2);
        assert_eq!(server.routes[0].path, "/ws");
        assert_eq!(server.routes[0].method, HttpMethod::GET);
        assert_eq!(server.routes[1].path, "/chat/:room");
        assert_eq!(server.routes[1].method, HttpMethod::GET);
    }

    #[test]
    fn test_route_method_matching() {
        let get_route = Route::new("/test", HttpMethod::GET, |_req| async {
            Ok(Response::ok())
        });
        let post_route = Route::new("/test", HttpMethod::POST, |_req| async {
            Ok(Response::ok())
        });

        // Routes with same path but different methods should be distinct
        assert_eq!(get_route.path, post_route.path);
        assert_ne!(get_route.method, post_route.method);
    }

    #[test]
    fn test_path_parameter_patterns() {
        // Test various parameter pattern formats
        let patterns = vec![
            ("/users/:id", "/users/123", vec![("id", "123")]),
            (
                "/users/:user_id/posts/:post_id",
                "/users/john/posts/hello",
                vec![("user_id", "john"), ("post_id", "hello")],
            ),
            (
                "/static/*file",
                "/static/css/style.css",
                vec![("file", "css/style.css")],
            ),
            (
                "/api/v:version/users",
                "/api/v1/users",
                vec![("version", "1")],
            ),
            (
                "/:category/:subcategory/:item",
                "/electronics/phones/iphone",
                vec![
                    ("category", "electronics"),
                    ("subcategory", "phones"),
                    ("item", "iphone"),
                ],
            ),
        ];

        for (pattern, path, expected_params) in patterns {
            let route = Route::new(pattern, HttpMethod::GET, |_req| async {
                Ok(Response::ok())
            });

            assert!(
                route.matches(path),
                "Pattern '{}' should match path '{}'",
                pattern,
                path
            );

            let extracted_params = route.extract_params(path);
            assert_eq!(extracted_params.len(), expected_params.len());

            for (key, expected_value) in expected_params {
                assert_eq!(
                    extracted_params.get(key),
                    Some(&expected_value.to_string()),
                    "Parameter '{}' should be '{}' for pattern '{}' and path '{}'",
                    key,
                    expected_value,
                    pattern,
                    path
                );
            }
        }
    }

    #[test]
    fn test_route_matching_edge_cases() {
        let route = Route::new("/users/:id", HttpMethod::GET, |_req| async {
            Ok(Response::ok())
        });

        // Test edge cases that should NOT match
        assert!(!route.matches("/users//123")); // Double slash
        assert!(!route.matches("/users/")); // Trailing slash with no param
        assert!(!route.matches("users/123")); // Missing leading slash
        assert!(!route.matches("/Users/123")); // Case sensitivity
        assert!(!route.matches("/users/123/")); // Trailing slash
        assert!(!route.matches("/users/123/extra")); // Extra segments
    }
}
