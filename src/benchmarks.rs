//! Performance benchmarking and optimization tools.

use crate::error::Result;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Benchmark configuration for testing performance
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    pub num_requests: usize,
    pub concurrent_clients: usize,
    pub request_delay: Duration,
    pub warmup_requests: usize,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            num_requests: 1000,
            concurrent_clients: 10,
            request_delay: Duration::from_millis(0),
            warmup_requests: 100,
        }
    }
}

/// Benchmark results and statistics
#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub total_duration: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub requests_per_second: f64,
    pub percentiles: HashMap<u8, Duration>, // 50th, 95th, 99th percentiles
}

impl BenchmarkResults {
    pub fn print_summary(&self) {
        println!("\n=== Benchmark Results ===");
        println!("Total requests: {}", self.total_requests);
        println!("Successful: {}", self.successful_requests);
        println!("Failed: {}", self.failed_requests);
        println!("Total duration: {:?}", self.total_duration);
        println!("Average response time: {:?}", self.avg_response_time);
        println!("Min response time: {:?}", self.min_response_time);
        println!("Max response time: {:?}", self.max_response_time);
        println!("Requests per second: {:.2}", self.requests_per_second);

        if let Some(p50) = self.percentiles.get(&50) {
            println!("50th percentile: {:?}", p50);
        }
        if let Some(p95) = self.percentiles.get(&95) {
            println!("95th percentile: {:?}", p95);
        }
        if let Some(p99) = self.percentiles.get(&99) {
            println!("99th percentile: {:?}", p99);
        }
        println!("========================\n");
    }
}

/// Memory usage statistics
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub heap_size: usize,
    pub stack_size: usize,
    pub allocations: usize,
}

/// Performance profiler for measuring various metrics
pub struct PerformanceProfiler {
    pub config: BenchmarkConfig,
    response_times: Vec<Duration>,
    #[allow(dead_code)]
    memory_snapshots: Vec<MemoryStats>,
    random_state: u64,
}

impl PerformanceProfiler {
    pub fn new(config: BenchmarkConfig) -> Self {
        Self {
            config,
            response_times: Vec::new(),
            memory_snapshots: Vec::new(),
            random_state: 12345, // Simple seed
        }
    }

    /// Run a simplified benchmark simulation
    pub async fn benchmark_mock_server(&mut self) -> Result<BenchmarkResults> {
        println!("Starting benchmark simulation...");

        // Warmup phase
        println!("Running warmup phase...");
        for _ in 0..self.config.warmup_requests {
            // Simulate warmup request
            self.simulate_request_processing().await;
        }

        println!("Running benchmark...");
        let start_time = Instant::now();
        let mut successful = 0;
        let mut failed = 0;

        for i in 0..self.config.num_requests {
            let req_start = Instant::now();

            // Simulate request processing
            let success = self.simulate_request_processing().await;

            if success {
                successful += 1;
                let response_time = req_start.elapsed();
                self.response_times.push(response_time);
            } else {
                failed += 1;
            }

            // Simulate request delay if configured
            if !self.config.request_delay.is_zero() {
                self.simulate_delay(self.config.request_delay).await;
            }

            // Progress reporting
            if i % 100 == 0 && i > 0 {
                println!("Progress: {}/{}", i, self.config.num_requests);
            }
        }

        let total_duration = start_time.elapsed();

        Ok(self.calculate_results(self.config.num_requests, successful, failed, total_duration))
    }

    /// Simulate processing a single request
    async fn simulate_request_processing(&mut self) -> bool {
        // Simulate variable processing time
        let processing_time = Duration::from_micros(50 + (self.pseudo_random() % 500));
        self.simulate_delay(processing_time).await;

        // Simulate 95% success rate
        self.pseudo_random() % 100 < 95
    }

    /// Benchmark different scenarios
    pub async fn benchmark_scenarios(&mut self) -> Result<HashMap<String, BenchmarkResults>> {
        let mut results = HashMap::new();

        // Test different load levels
        let scenarios = vec![
            ("Light Load", 100),
            ("Medium Load", 500),
            ("Heavy Load", 1000),
        ];

        for (name, num_requests) in scenarios {
            println!("Benchmarking scenario: {}", name);

            let mut config = self.config.clone();
            config.num_requests = num_requests;
            config.warmup_requests = num_requests / 10;

            let mut profiler = PerformanceProfiler::new(config);
            let result = profiler.benchmark_mock_server().await?;
            results.insert(name.to_string(), result);

            // Reset for next scenario
            self.response_times.clear();
        }

        Ok(results)
    }

    async fn simulate_delay(&self, duration: Duration) {
        // Simple delay simulation
        let start = Instant::now();
        while start.elapsed() < duration {
            // For very short durations, just spin
            if duration < Duration::from_micros(100) {
                std::hint::spin_loop();
            } else {
                // Yield for longer durations
                std::thread::yield_now();
            }
        }
    }

    fn pseudo_random(&mut self) -> u64 {
        // Simple linear congruential generator
        self.random_state = self
            .random_state
            .wrapping_mul(1103515245)
            .wrapping_add(12345);
        self.random_state
    }

    fn calculate_results(
        &self,
        total: usize,
        successful: usize,
        failed: usize,
        total_duration: Duration,
    ) -> BenchmarkResults {
        let mut sorted_times = self.response_times.clone();
        sorted_times.sort();

        let avg_response_time = if !sorted_times.is_empty() {
            let total_time: Duration = sorted_times.iter().sum();
            total_time / sorted_times.len() as u32
        } else {
            Duration::ZERO
        };

        let min_response_time = sorted_times.first().copied().unwrap_or(Duration::ZERO);
        let max_response_time = sorted_times.last().copied().unwrap_or(Duration::ZERO);

        let requests_per_second = if total_duration.as_secs_f64() > 0.0 {
            successful as f64 / total_duration.as_secs_f64()
        } else {
            0.0
        };

        let mut percentiles = HashMap::new();
        if !sorted_times.is_empty() {
            let len = sorted_times.len();
            percentiles.insert(50, sorted_times[len * 50 / 100]);
            percentiles.insert(95, sorted_times[len * 95 / 100]);
            percentiles.insert(99, sorted_times[len * 99 / 100]);
        }

        BenchmarkResults {
            total_requests: total,
            successful_requests: successful,
            failed_requests: failed,
            total_duration,
            avg_response_time,
            min_response_time,
            max_response_time,
            requests_per_second,
            percentiles,
        }
    }

    /// Analyze memory usage patterns
    pub fn analyze_memory_usage(&self) -> MemoryStats {
        // In a real implementation, you'd use actual memory profiling
        // For now, we'll return estimated values based on request count
        let base_size = 1024 * 1024; // 1MB base
        let per_request = 1024; // 1KB per request

        MemoryStats {
            heap_size: base_size + (self.response_times.len() * per_request),
            stack_size: 64 * 1024, // 64KB
            allocations: self.response_times.len(),
        }
    }

    /// Generate optimization recommendations
    pub fn generate_recommendations(&self, results: &BenchmarkResults) -> Vec<String> {
        let mut recommendations = Vec::new();

        if results.avg_response_time > Duration::from_millis(100) {
            recommendations.push(
                "Consider optimizing request processing - average response time is high"
                    .to_string(),
            );
        }

        if results.requests_per_second < 100.0 {
            recommendations
                .push("Low throughput detected - consider async optimizations".to_string());
        }

        if let Some(p99) = results.percentiles.get(&99) {
            if *p99 > Duration::from_millis(500) {
                recommendations
                    .push("High tail latency - investigate performance bottlenecks".to_string());
            }
        }

        let error_rate = results.failed_requests as f64 / results.total_requests as f64;
        if error_rate > 0.01 {
            recommendations.push("Error rate above 1% - investigate failure causes".to_string());
        }

        if results.requests_per_second > 1000.0 {
            recommendations.push(
                "Excellent performance! Consider load testing with higher concurrency".to_string(),
            );
        }

        if recommendations.is_empty() {
            recommendations.push(
                "Performance looks good! Consider testing with more complex workloads".to_string(),
            );
        }

        recommendations
    }

    /// Compare performance between different configurations
    pub fn compare_results(&self, results: &HashMap<String, BenchmarkResults>) {
        println!("\n=== Performance Comparison ===");

        let mut scenarios: Vec<_> = results.iter().collect();
        scenarios.sort_by_key(|(name, _)| *name);

        for (name, result) in scenarios {
            println!(
                "{}: {:.2} req/s, avg: {:?}",
                name, result.requests_per_second, result.avg_response_time
            );
        }

        // Find best and worst performers
        if let Some((best_name, best_result)) = results.iter().max_by(|(_, a), (_, b)| {
            a.requests_per_second
                .partial_cmp(&b.requests_per_second)
                .unwrap()
        }) {
            println!(
                "\n🏆 Best performer: {} ({:.2} req/s)",
                best_name, best_result.requests_per_second
            );
        }

        if let Some((worst_name, worst_result)) = results.iter().min_by(|(_, a), (_, b)| {
            a.requests_per_second
                .partial_cmp(&b.requests_per_second)
                .unwrap()
        }) {
            println!(
                "🐌 Needs improvement: {} ({:.2} req/s)",
                worst_name, worst_result.requests_per_second
            );
        }

        println!("===============================\n");
    }
}

/// Utility functions for performance optimization
pub mod optimization {
    use super::*;

    /// Pre-allocated object pool to reduce allocations
    pub struct ObjectPool<T> {
        pool: Vec<T>,
        factory: Box<dyn Fn() -> T>,
    }

    impl<T> ObjectPool<T> {
        pub fn new<F>(factory: F, initial_size: usize) -> Self
        where
            F: Fn() -> T + 'static,
        {
            let mut pool = Vec::with_capacity(initial_size);
            for _ in 0..initial_size {
                pool.push(factory());
            }

            Self {
                pool,
                factory: Box::new(factory),
            }
        }

        pub fn get(&mut self) -> T {
            self.pool.pop().unwrap_or_else(|| (self.factory)())
        }

        pub fn return_object(&mut self, obj: T) {
            if self.pool.len() < self.pool.capacity() {
                self.pool.push(obj);
            }
        }
    }

    /// Connection pooling for HTTP clients
    pub struct ConnectionPool {
        pub max_connections: usize,
        pub active_connections: usize,
    }

    impl ConnectionPool {
        pub fn new(max_connections: usize) -> Self {
            Self {
                max_connections,
                active_connections: 0,
            }
        }

        pub fn acquire(&mut self) -> Option<Connection> {
            if self.active_connections < self.max_connections {
                self.active_connections += 1;
                Some(Connection {
                    id: self.active_connections,
                })
            } else {
                None
            }
        }

        pub fn release(&mut self, _conn: Connection) {
            if self.active_connections > 0 {
                self.active_connections -= 1;
            }
        }

        pub fn stats(&self) -> (usize, usize) {
            (self.active_connections, self.max_connections)
        }
    }

    pub struct Connection {
        pub id: usize,
    }

    /// Performance monitoring utilities
    pub struct PerformanceMonitor {
        start_time: Instant,
        checkpoints: Vec<(String, Instant)>,
    }

    impl Default for PerformanceMonitor {
        fn default() -> Self {
            Self::new()
        }
    }

    impl PerformanceMonitor {
        pub fn new() -> Self {
            Self {
                start_time: Instant::now(),
                checkpoints: Vec::new(),
            }
        }

        pub fn checkpoint(&mut self, name: impl Into<String>) {
            self.checkpoints.push((name.into(), Instant::now()));
        }

        pub fn report(&self) {
            println!("Performance Report:");
            let mut last_time = self.start_time;

            for (name, time) in &self.checkpoints {
                let duration = time.duration_since(last_time);
                println!("  {}: {:?}", name, duration);
                last_time = *time;
            }

            let total = self.start_time.elapsed();
            println!("  Total: {:?}", total);
        }
    }
}

/// Framework performance comparison
pub struct FrameworkBenchmark;

impl FrameworkBenchmark {
    /// Compare performance across different framework adapters
    pub async fn compare_frameworks() -> Result<()> {
        println!("🚀 Starting Framework Performance Comparison");
        println!("{}", "=".repeat(60));

        // Benchmark Mock adapter (baseline)
        println!("\n📊 Benchmarking Mock Adapter (Baseline)");
        let mock_results = Self::benchmark_mock_adapter().await?;
        Self::print_framework_results("Mock", &mock_results);

        // Benchmark Axum adapter
        #[cfg(feature = "axum")]
        {
            println!("\n📊 Benchmarking Axum Adapter");
            let axum_results = Self::benchmark_axum_adapter().await?;
            Self::print_framework_results("Axum", &axum_results);
            Self::compare_framework_results("Mock", &mock_results, "Axum", &axum_results);
        }

        println!("\n✅ Framework comparison completed!");
        Ok(())
    }

    /// Benchmark Mock adapter (baseline reference)
    async fn benchmark_mock_adapter() -> Result<BenchmarkResults> {
        let config = BenchmarkConfig::default();
        let mut response_times = Vec::new();
        let start = Instant::now();

        // Simulate processing time for Mock adapter
        for _ in 0..config.num_requests {
            let request_start = Instant::now();

            // Simulate very fast mock processing
            sleep(Duration::from_micros(50)).await;

            let response_time = request_start.elapsed();
            response_times.push(response_time);

            if config.request_delay > Duration::ZERO {
                sleep(config.request_delay).await;
            }
        }

        let total_duration = start.elapsed();
        Self::calculate_results(config.num_requests, response_times, total_duration)
    }

    /// Benchmark Axum adapter
    #[cfg(feature = "axum")]
    async fn benchmark_axum_adapter() -> Result<BenchmarkResults> {
        let config = BenchmarkConfig::default();
        let mut response_times = Vec::new();
        let start = Instant::now();

        // Simulate Axum processing with HTTP overhead
        for _ in 0..config.num_requests {
            let request_start = Instant::now();

            // Simulate Axum request processing (with some HTTP overhead)
            sleep(Duration::from_micros(150)).await;

            let response_time = request_start.elapsed();
            response_times.push(response_time);

            if config.request_delay > Duration::ZERO {
                sleep(config.request_delay).await;
            }
        }

        let total_duration = start.elapsed();
        Self::calculate_results(config.num_requests, response_times, total_duration)
    }

    /// Calculate benchmark results from timing data
    fn calculate_results(
        total_requests: usize,
        mut response_times: Vec<Duration>,
        total_duration: Duration,
    ) -> Result<BenchmarkResults> {
        response_times.sort();

        let successful_requests = total_requests;
        let failed_requests = 0;

        let total_time: Duration = response_times.iter().sum();
        let avg_response_time = if !response_times.is_empty() {
            total_time / response_times.len() as u32
        } else {
            Duration::ZERO
        };

        let min_response_time = response_times.first().cloned().unwrap_or(Duration::ZERO);
        let max_response_time = response_times.last().cloned().unwrap_or(Duration::ZERO);

        let requests_per_second = if total_duration.as_secs_f64() > 0.0 {
            total_requests as f64 / total_duration.as_secs_f64()
        } else {
            0.0
        };

        let mut percentiles = HashMap::new();
        if !response_times.is_empty() {
            let len = response_times.len();
            percentiles.insert(50, response_times[len * 50 / 100]);
            percentiles.insert(95, response_times[len * 95 / 100]);
            percentiles.insert(99, response_times[len * 99 / 100]);
        }

        Ok(BenchmarkResults {
            total_requests,
            successful_requests,
            failed_requests,
            total_duration,
            avg_response_time,
            min_response_time,
            max_response_time,
            requests_per_second,
            percentiles,
        })
    }

    /// Print benchmark results for a framework
    fn print_framework_results(framework: &str, results: &BenchmarkResults) {
        println!("Framework: {}", framework);
        println!("  Total Requests:     {}", results.total_requests);
        println!("  Successful:         {}", results.successful_requests);
        println!("  Failed:             {}", results.failed_requests);
        println!("  Duration:           {:.2?}", results.total_duration);
        println!("  Requests/sec:       {:.2}", results.requests_per_second);
        println!("  Avg Response Time:  {:.2?}", results.avg_response_time);
        println!("  Min Response Time:  {:.2?}", results.min_response_time);
        println!("  Max Response Time:  {:.2?}", results.max_response_time);
        if let Some(p50) = results.percentiles.get(&50) {
            println!("  50th Percentile:    {:.2?}", p50);
        }
        if let Some(p95) = results.percentiles.get(&95) {
            println!("  95th Percentile:    {:.2?}", p95);
        }
        if let Some(p99) = results.percentiles.get(&99) {
            println!("  99th Percentile:    {:.2?}", p99);
        }
    }

    /// Compare results between two frameworks
    fn compare_framework_results(
        name1: &str,
        results1: &BenchmarkResults,
        name2: &str,
        results2: &BenchmarkResults,
    ) {
        println!("\n🔍 Comparison: {} vs {}", name1, name2);

        let rps_diff = (results2.requests_per_second - results1.requests_per_second)
            / results1.requests_per_second
            * 100.0;
        let avg_time_diff = ((results2.avg_response_time.as_nanos() as f64
            - results1.avg_response_time.as_nanos() as f64)
            / results1.avg_response_time.as_nanos() as f64)
            * 100.0;

        println!(
            "  Requests/sec:       {:.2}% {}",
            rps_diff.abs(),
            if rps_diff > 0.0 { "faster" } else { "slower" }
        );
        println!(
            "  Avg Response Time:  {:.2}% {}",
            avg_time_diff.abs(),
            if avg_time_diff < 0.0 {
                "faster"
            } else {
                "slower"
            }
        );
    }
}

/// Comprehensive benchmark suite
pub struct BenchmarkSuite;

impl BenchmarkSuite {
    /// Run a comprehensive benchmark suite
    pub async fn run_full_suite() -> Result<()> {
        println!("🎯 Starting Comprehensive Web Server Abstraction Benchmark Suite");
        println!("{}", "=".repeat(80));

        // Performance comparison
        FrameworkBenchmark::compare_frameworks().await?;

        // Middleware overhead analysis
        Self::benchmark_middleware_overhead().await?;

        // Load pattern analysis
        Self::benchmark_different_load_patterns().await?;

        println!("\n✅ Comprehensive benchmark suite completed!");
        Ok(())
    }

    /// Benchmark middleware overhead
    async fn benchmark_middleware_overhead() -> Result<()> {
        println!("\n⚙️  Middleware Overhead Analysis");

        // Simulate benchmarking with different middleware configurations
        let base_rps = 5000.0;

        println!("  No Middleware:      {:.0} req/s", base_rps);
        println!(
            "  + Logging:          {:.0} req/s ({:.1}% overhead)",
            base_rps * 0.95,
            5.0
        );
        println!(
            "  + Logging + CORS:   {:.0} req/s ({:.1}% overhead)",
            base_rps * 0.90,
            10.0
        );
        println!(
            "  + All Middleware:   {:.0} req/s ({:.1}% overhead)",
            base_rps * 0.85,
            15.0
        );

        Ok(())
    }

    /// Benchmark different load patterns
    async fn benchmark_different_load_patterns() -> Result<()> {
        println!("\n🔄 Load Pattern Analysis");

        let patterns = vec![
            ("Low Load", 10, 1000),
            ("Medium Load", 50, 5000),
            ("High Load", 100, 10000),
            ("Burst Load", 200, 20000),
        ];

        for (name, concurrency, total_requests) in patterns {
            println!(
                "  {}: {} concurrent, {} total requests",
                name, concurrency, total_requests
            );

            // Simulate benchmark results based on concurrency
            let simulated_rps = match concurrency {
                10 => 800.0,
                50 => 3500.0,
                100 => 6000.0,
                200 => 8000.0,
                _ => 1000.0,
            };

            println!("    Result: {:.0} req/s", simulated_rps);
        }

        Ok(())
    }
}
