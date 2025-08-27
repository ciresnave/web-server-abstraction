//! Advanced example showcasing expanded middleware and performance features.

use std::time::Duration;
use web_server_abstraction::{
    HttpMethod, PerformanceProfiler, Response, StatusCode, WebServer, benchmarks::BenchmarkConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Advanced Web Server Abstraction Demo");
    println!("=========================================\n");

    // Create server with route configuration
    let _server = create_demo_server();

    // Run performance benchmarks
    run_benchmarks().await?;

    println!("✅ Demo completed successfully!");
    Ok(())
}

fn create_demo_server() -> WebServer {
    println!("🔧 Setting up server with route configuration...");

    let server = WebServer::with_mock_adapter()
        .route("/health", HttpMethod::GET, |_req| async {
            Ok(Response::new(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(r#"{"status": "healthy", "timestamp": 1234567890}"#))
        })
        .route("/api/info", HttpMethod::GET, |_req| async {
            let info = r#"{
                "name": "Web Server Abstraction Demo",
                "version": "1.0.0",
                "features": [
                    "multi-framework support",
                    "advanced middleware",
                    "performance benchmarking",
                    "rate limiting",
                    "authentication",
                    "caching",
                    "compression"
                ],
                "supported_frameworks": [
                    "Mock (testing)",
                    "Axum",
                    "Actix-Web",
                    "Warp"
                ]
            }"#;

            Ok(Response::new(StatusCode::OK)
                .header("Content-Type", "application/json")
                .header("X-Total-Count", "4")
                .body(info))
        })
        .route("/api/protected", HttpMethod::POST, |req: web_server_abstraction::Request| async move {
            // This route would require proper authentication
            if req.headers.get("authorization").is_some() {
                Ok(Response::new(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(r#"{"message": "Access granted to protected resource"}"#))
            } else {
                Ok(Response::new(StatusCode::UNAUTHORIZED)
                    .header("Content-Type", "application/json")
                    .body(r#"{"error": "Authentication required"}"#))
            }
        })
        .route("/api/large", HttpMethod::GET, |_req| async {
            // Large response for testing
            let large_data = format!(r#"{{
                "data": [{}],
                "metadata": {{
                    "total_items": 100,
                    "generated_at": "2024-01-01T00:00:00Z",
                    "description": "This is a large JSON response designed to test compression middleware."
                }}
            }}"#, (0..100).map(|i| format!(r#""Item {}: Large content for testing compression""#, i)).collect::<Vec<_>>().join(","));

            Ok(Response::new(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(large_data))
        })
        .route("/api/error", HttpMethod::GET, |_req| async {
            Err(web_server_abstraction::WebServerError::custom(
                "Simulated error for testing"
            ))
        });

    println!("✅ Routes configured:");
    println!("   • GET  /health - Health check");
    println!("   • GET  /api/info - API information");
    println!("   • POST /api/protected - Protected resource");
    println!("   • GET  /api/large - Large response (compression test)");
    println!("   • GET  /api/error - Error simulation\n");

    server
}

async fn run_benchmarks() -> Result<(), Box<dyn std::error::Error>> {
    println!("📊 Running performance benchmarks...");
    println!("=====================================\n");

    // Configure benchmark parameters
    let config = BenchmarkConfig {
        num_requests: 500,
        concurrent_clients: 5,
        request_delay: Duration::from_millis(1),
        warmup_requests: 50,
    };

    let mut profiler = PerformanceProfiler::new(config);

    // Run benchmark simulation
    println!("🏃 Running benchmark simulation...");
    let results = profiler.benchmark_mock_server().await?;

    // Display results
    results.print_summary();

    // Generate optimization recommendations
    let recommendations = profiler.generate_recommendations(&results);
    println!("💡 Optimization Recommendations:");
    for (i, rec) in recommendations.iter().enumerate() {
        println!("   {}. {}", i + 1, rec);
    }
    println!();

    // Memory analysis
    let memory_stats = profiler.analyze_memory_usage();
    println!("🧠 Memory Usage Analysis:");
    println!(
        "   • Estimated heap size: {} KB",
        memory_stats.heap_size / 1024
    );
    println!(
        "   • Estimated stack size: {} KB",
        memory_stats.stack_size / 1024
    );
    println!("   • Request allocations: {}", memory_stats.allocations);
    println!();

    // Scenario comparison
    println!("🔄 Comparing different scenarios...");
    let scenario_results = profiler.benchmark_scenarios().await?;
    profiler.compare_results(&scenario_results);

    println!("✅ Benchmarking completed!");
    Ok(())
}
