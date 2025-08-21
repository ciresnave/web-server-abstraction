use web_server_abstraction::benchmarks::{BenchmarkSuite, FrameworkBenchmark};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎯 Web Server Abstraction Performance Benchmark");
    println!("===============================================");

    // Run comprehensive benchmark suite
    BenchmarkSuite::run_full_suite().await?;

    // Run focused framework comparison
    println!("\n{}", "=".repeat(60));
    println!("🔄 Running Focused Framework Comparison");
    FrameworkBenchmark::compare_frameworks().await?;

    println!("\n✅ All benchmarks completed successfully!");
    Ok(())
}
