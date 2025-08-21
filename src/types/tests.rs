//! Unit tests for core types

use super::*;
use crate::error::WebServerError;
use bytes::Bytes;
use http::{Method, Uri};
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_conversions() {
        // Test all HTTP method conversions
        assert_eq!(HttpMethod::GET.as_str(), "GET");
        assert_eq!(HttpMethod::POST.as_str(), "POST");
        assert_eq!(HttpMethod::PUT.as_str(), "PUT");
        assert_eq!(HttpMethod::DELETE.as_str(), "DELETE");
        assert_eq!(HttpMethod::PATCH.as_str(), "PATCH");
        assert_eq!(HttpMethod::HEAD.as_str(), "HEAD");
        assert_eq!(HttpMethod::OPTIONS.as_str(), "OPTIONS");
        assert_eq!(HttpMethod::TRACE.as_str(), "TRACE");
        assert_eq!(HttpMethod::CONNECT.as_str(), "CONNECT");

        // Test conversion from http::Method
        assert_eq!(HttpMethod::from(Method::GET), HttpMethod::GET);
        assert_eq!(HttpMethod::from(Method::POST), HttpMethod::POST);
        assert_eq!(HttpMethod::from(Method::PUT), HttpMethod::PUT);
        assert_eq!(HttpMethod::from(Method::DELETE), HttpMethod::DELETE);
        assert_eq!(HttpMethod::from(Method::PATCH), HttpMethod::PATCH);
        assert_eq!(HttpMethod::from(Method::HEAD), HttpMethod::HEAD);
        assert_eq!(HttpMethod::from(Method::OPTIONS), HttpMethod::OPTIONS);
        assert_eq!(HttpMethod::from(Method::TRACE), HttpMethod::TRACE);
        assert_eq!(HttpMethod::from(Method::CONNECT), HttpMethod::CONNECT);

        // Test conversion to http::Method
        assert_eq!(Method::from(HttpMethod::GET), Method::GET);
        assert_eq!(Method::from(HttpMethod::POST), Method::POST);
        assert_eq!(Method::from(HttpMethod::PUT), Method::PUT);
        assert_eq!(Method::from(HttpMethod::DELETE), Method::DELETE);
        assert_eq!(Method::from(HttpMethod::PATCH), Method::PATCH);
        assert_eq!(Method::from(HttpMethod::HEAD), Method::HEAD);
        assert_eq!(Method::from(HttpMethod::OPTIONS), Method::OPTIONS);
        assert_eq!(Method::from(HttpMethod::TRACE), Method::TRACE);
        assert_eq!(Method::from(HttpMethod::CONNECT), Method::CONNECT);
    }

    #[test]
    fn test_status_code_creation() {
        // Test common status codes
        assert_eq!(StatusCode::OK.0, 200);
        assert_eq!(StatusCode::CREATED.0, 201);
        assert_eq!(StatusCode::BAD_REQUEST.0, 400);
        assert_eq!(StatusCode::NOT_FOUND.0, 404);
        assert_eq!(StatusCode::INTERNAL_SERVER_ERROR.0, 500);

        // Test custom status code
        let custom = StatusCode::new(418);
        assert_eq!(custom.0, 418);
    }

    #[test]
    fn test_request_creation_and_path_params() {
        let uri: Uri = "/users/123".parse().unwrap();
        let mut request = Request::new(HttpMethod::GET, uri);

        // Test path extraction
        assert_eq!(request.path(), "/users/123");

        // Test path parameter functionality
        assert!(request.param("id").is_none()); // No params set yet

        // Set path parameters
        let mut params = HashMap::new();
        params.insert("id".to_string(), "123".to_string());
        params.insert("name".to_string(), "john".to_string());
        request.set_params(params);

        // Test parameter retrieval
        assert_eq!(request.param("id"), Some("123"));
        assert_eq!(request.param("name"), Some("john"));
        assert_eq!(request.param("nonexistent"), None);

        // Test all parameters
        let all_params = request.params();
        assert_eq!(all_params.len(), 2);
        assert_eq!(all_params.get("id"), Some(&"123".to_string()));
        assert_eq!(all_params.get("name"), Some(&"john".to_string()));
    }

    #[test]
    fn test_request_with_query_params() {
        let uri: Uri = "/search?q=rust&limit=10".parse().unwrap();
        let request = Request::new(HttpMethod::GET, uri);

        assert_eq!(request.path(), "/search");
        assert_eq!(request.query(), Some("q=rust&limit=10"));
    }

    #[tokio::test]
    async fn test_request_json_parsing() {
        let uri: Uri = "/api/test".parse().unwrap();
        let mut request = Request::new(HttpMethod::POST, uri);

        // Set JSON body
        let json_data = r#"{"name": "test", "value": 42}"#;
        request.body = Body::from(json_data.as_bytes().to_vec());

        // Test JSON parsing
        #[derive(serde::Deserialize, PartialEq, Debug)]
        struct TestData {
            name: String,
            value: i32,
        }

        let parsed: TestData = request.json().await.unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.value, 42);
    }

    #[tokio::test]
    async fn test_request_text_parsing() {
        let uri: Uri = "/api/test".parse().unwrap();
        let mut request = Request::new(HttpMethod::POST, uri);

        // Set text body
        let text_data = "Hello, World!";
        request.body = Body::from(text_data.as_bytes().to_vec());

        // Test text parsing
        let parsed_text = request.text().await.unwrap();
        assert_eq!(parsed_text, "Hello, World!");
    }

    #[tokio::test]
    async fn test_request_json_parsing_error() {
        let uri: Uri = "/api/test".parse().unwrap();
        let mut request = Request::new(HttpMethod::POST, uri);

        // Set invalid JSON body
        request.body = Body::from(b"invalid json".to_vec());

        // Test JSON parsing error
        #[derive(serde::Deserialize)]
        struct TestData {
            name: String,
        }

        let result: Result<TestData, WebServerError> = request.json().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebServerError::JsonError(_)));
    }

    #[test]
    fn test_response_creation_and_chaining() {
        // Test basic response creation
        let response = Response::ok();
        assert_eq!(response.status, StatusCode::OK);

        // Test response with custom status
        let response = Response::new(StatusCode::CREATED);
        assert_eq!(response.status, StatusCode::CREATED);

        // Test method chaining
        let response = Response::ok()
            .body("Hello")
            .header("Content-Type", "text/plain")
            .header("X-Custom", "test");

        assert_eq!(response.body.to_string(), "Hello");
        assert_eq!(
            response.headers.get("Content-Type"),
            Some(&"text/plain".to_string())
        );
        assert_eq!(response.headers.get("X-Custom"), Some(&"test".to_string()));
    }

    #[test]
    fn test_response_json_creation() {
        #[derive(serde::Serialize)]
        struct TestData {
            message: String,
            code: i32,
        }

        let data = TestData {
            message: "success".to_string(),
            code: 200,
        };

        let response = Response::json(&data).unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );

        // Verify JSON content
        let body_str = response.body.to_string();
        assert!(body_str.contains("success"));
        assert!(body_str.contains("200"));
    }

    #[test]
    fn test_headers_manipulation() {
        let mut headers = Headers::new();

        // Test adding headers
        headers.insert("Content-Type", "application/json");
        headers.insert("Authorization", "Bearer token123");

        assert_eq!(
            headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );
        assert_eq!(
            headers.get("Authorization"),
            Some(&"Bearer token123".to_string())
        );
        assert_eq!(headers.get("NonExistent"), None);

        // Test case insensitive lookup
        assert_eq!(
            headers.get("content-type"),
            Some(&"application/json".to_string())
        );
        assert_eq!(
            headers.get("CONTENT-TYPE"),
            Some(&"application/json".to_string())
        );

        // Test header removal
        headers.remove("Authorization");
        assert_eq!(headers.get("Authorization"), None);
    }

    #[test]
    fn test_body_creation_and_conversion() {
        // Test empty body
        let empty_body = Body::empty();
        assert_eq!(empty_body.to_string(), "");

        // Test string body
        let string_body = Body::from("Hello, World!".to_string());
        assert_eq!(string_body.to_string(), "Hello, World!");

        // Test bytes body
        let bytes_body = Body::from(b"Binary data".to_vec());
        assert_eq!(bytes_body.to_string(), "Binary data");

        // Test bytes conversion
        let bytes = Bytes::from("Test data");
        let bytes_body = Body::from(bytes);
        assert_eq!(bytes_body.to_string(), "Test data");
    }

    #[tokio::test]
    async fn test_body_bytes_extraction() {
        let body = Body::from("Test content".to_string());
        let bytes = body.bytes().await.unwrap();
        assert_eq!(bytes, Bytes::from("Test content"));
    }

    #[test]
    fn test_websocket_upgrade_creation() {
        let uri: Uri = "/ws".parse().unwrap();
        let mut request = Request::new(HttpMethod::GET, uri);

        // Add WebSocket headers
        request.headers.insert("Upgrade", "websocket");
        request.headers.insert("Connection", "Upgrade");
        request
            .headers
            .insert("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        request.headers.insert("Sec-WebSocket-Version", "13");

        let upgrade_result = WebSocketUpgrade::from_request(request);
        assert!(upgrade_result.is_ok());

        let upgrade = upgrade_result.unwrap();
        assert_eq!(upgrade.key, "dGhlIHNhbXBsZSBub25jZQ==");
    }

    #[test]
    fn test_websocket_key_generation() {
        let upgrade = WebSocketUpgrade {
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        };

        let accept_key = upgrade.generate_accept_key();

        // The expected value for the test key according to RFC 6455
        assert_eq!(accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_websocket_key_generation_different_keys() {
        // Test with different keys to ensure algorithm works correctly
        let test_cases = vec![
            ("dGhlIHNhbXBsZSBub25jZQ==", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ("AQIDBAUGBwgJCgsMDQ4PEC==", "Kfh9QIsMVZcl6xEPYxPHzW8SZ8w="),
        ];

        for (key, expected) in test_cases {
            let upgrade = WebSocketUpgrade {
                key: key.to_string(),
            };
            let accept_key = upgrade.generate_accept_key();
            assert_eq!(accept_key, expected, "Failed for key: {}", key);
        }
    }

    #[test]
    fn test_websocket_upgrade_missing_headers() {
        let uri: Uri = "/ws".parse().unwrap();
        let request = Request::new(HttpMethod::GET, uri);

        // Missing required WebSocket headers
        let upgrade_result = WebSocketUpgrade::from_request(request);
        assert!(upgrade_result.is_err());
    }

    #[test]
    fn test_websocket_message_types() {
        // Test WebSocket message creation
        let text_msg = WebSocketMessage::Text("Hello".to_string());
        let binary_msg = WebSocketMessage::Binary(vec![1, 2, 3, 4]);
        let ping_msg = WebSocketMessage::Ping(vec![]);
        let pong_msg = WebSocketMessage::Pong(vec![]);
        let close_msg = WebSocketMessage::Close(Some(WebSocketCloseCode::Normal));

        // Verify message types
        match text_msg {
            WebSocketMessage::Text(ref content) => assert_eq!(content, "Hello"),
            _ => panic!("Expected text message"),
        }

        match binary_msg {
            WebSocketMessage::Binary(ref data) => assert_eq!(data, &vec![1, 2, 3, 4]),
            _ => panic!("Expected binary message"),
        }

        match close_msg {
            WebSocketMessage::Close(Some(code)) => assert_eq!(code, WebSocketCloseCode::Normal),
            _ => panic!("Expected close message with normal code"),
        }
    }

    #[test]
    fn test_websocket_close_codes() {
        // Test WebSocket close code values
        assert_eq!(WebSocketCloseCode::Normal as u16, 1000);
        assert_eq!(WebSocketCloseCode::GoingAway as u16, 1001);
        assert_eq!(WebSocketCloseCode::ProtocolError as u16, 1002);
        assert_eq!(WebSocketCloseCode::UnsupportedData as u16, 1003);
        assert_eq!(WebSocketCloseCode::InvalidFramePayloadData as u16, 1007);
        assert_eq!(WebSocketCloseCode::PolicyViolation as u16, 1008);
        assert_eq!(WebSocketCloseCode::MessageTooBig as u16, 1009);
        assert_eq!(WebSocketCloseCode::InternalError as u16, 1011);
    }
}
