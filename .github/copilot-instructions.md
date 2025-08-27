# Web Server Abstraction Project

This project provides an ergonomic abstraction layer over popular Rust web frameworks.

## Project Overview
Web Server Abstraction is a high-performance, ergonomic Rust abstraction library over all of the popular web frameworks designed to be THE premier Rust web development solution to code toward. Focus on exceptional performance, comprehensive security, cross-platform compatibility, and multi-language SDK support.

## Core Principles

### SOLID Principles
- **Single Responsibility Principle (SRP)**: Each module, struct, and function serves one clear purpose
- **Open/Closed Principle (OCP)**: Design for extension without modification of existing code
- **Liskov Substitution Principle (LSP)**: Ensure proper inheritance and trait implementations
- **Interface Segregation Principle (ISP)**: Create focused, minimal trait interfaces
- **Dependency Inversion Principle (DIP)**: Depend on abstractions, not concretions

### Design Principles
- **DRY (Don't Repeat Yourself)**: Eliminate code duplication through proper abstraction
- **KISS (Keep It Simple, Stupid)**: Prefer simple, clear solutions over complex ones
- **Law of Demeter**: Minimize coupling between modules
- **Boy Scout Rule**: Always leave code cleaner than you found it
- **Polymorphism over Conditionals**: Use traits and generics instead of match/if chains

### Architecture Guidelines
- **Centralized Configuration**: All settings managed through unified config system
- **Minimal Dependencies**: Only essential external crates, prefer std library
- **Purposeful Layers**: Clear separation between protocol, core logic, and I/O layers
- **Avoid Over-engineering**: Build what's needed, not what might be needed

## Quality Standards

### Performance Requirements
- **Ultra-low Latency**: Every operation optimized for minimal delay
- **Memory Efficiency**: Zero-copy operations where possible
- **Concurrent by Design**: Async/await throughout, proper resource sharing

### Security Requirements
- **Security by Default**: All communications encrypted, secure defaults only
- **No Security Fallbacks**: Reject insecure connections rather than downgrade
- **Configurable Security**: Admin/user control over security requirements

### Testing Standards
- **Test-Driven Development**: Write tests before implementation
- **No Mocking**: Real implementations only, except for external system boundaries
- **Comprehensive Coverage**: Unit, integration, and property-based tests

### Documentation Requirements
- **Live Documentation**: Update docs with every code change
- **Multiple Audiences**: Admin guides, developer docs, contributor guides
- **Decision Log**: Document all architectural decisions with rationale

## Rust-Specific Guidelines

### Code Style
- Use `cargo fmt` and `cargo clippy` standards
- Prefer explicit types in public APIs
- Use `Result<T, E>` for all fallible operations
- Leverage zero-cost abstractions

### Error Handling
- Custom error types with `thiserror`
- Propagate errors with `?` operator
- Provide meaningful error context

### Async Programming
- Use `tokio` for async runtime
- Prefer `async fn` over manual `Future` implementations
- Handle cancellation properly with `select!`

## Project Structure
- Core library in `src/lib.rs`
- Binary targets in `src/bin/`
- FFI bindings in `ffi/` subdirectories
- Tests co-located with code
- Integration tests in `tests/`
- Documentation in `docs/`

## Cross-Platform Considerations
- Use conditional compilation for OS-specific code
- Abstract OS interfaces behind traits
- Test on all target platforms
- Minimize platform-specific dependencies

## Multi-Language SDK Guidelines
- C-compatible FFI layer as foundation
- Language-specific wrappers for ergonomics
- Consistent API design across languages
- Comprehensive examples for each language

## Project Status
- [x] Project scaffolding complete
- [x] Core abstraction traits defined
- [x] Framework adapters implemented (All frameworks working: Mock, Axum, Actix-Web, Warp, Rocket, Salvo, Poem)
- [x] Middleware system complete
- [x] Type system and error handling complete
- [x] Documentation and examples complete
- [x] Tests passing (107/107 tests)
- [x] Example applications working

## Architecture
- Core traits for web server abstraction in `src/core.rs`
- Framework-specific adapters in `src/adapters/`
- Built-in middleware system in `src/middleware.rs`
- Standardized HTTP types in `src/types.rs`
- Comprehensive error handling in `src/error.rs`

## Key Features
- Framework-agnostic web server interface
- Support for multiple web frameworks via feature flags
- Composable middleware system
- Type-safe request/response handling
- Built on modern async Rust patterns
- Mock adapter for easy testing

## Working Framework Adapters
- ✅ **Mock**: Testing adapter (always working)
- ✅ **Axum**: Production-ready adapter for Axum 0.8+
- ✅ **Actix-Web**: Production-ready adapter for Actix-Web 4.9+
- ✅ **Warp**: Production-ready adapter for Warp 0.4+
- ✅ **Rocket**: Production-ready adapter for Rocket 0.5+
- ✅ **Salvo**: Production-ready adapter for Salvo 0.82+
- ✅ **Poem**: Production-ready adapter for Poem 3.1+

## Critical Guidelines for Future Development

### 🚨 NEVER DISABLE - ALWAYS FIX 🚨
**When framework updates cause compilation errors:**

1. **DO NOT comment out modules in `src/adapters/mod.rs`**
2. **DO NOT comment out dependencies in `Cargo.toml`**
3. **DO NOT disable features to "fix" compilation**

**INSTEAD - ALWAYS FIX THE ROOT CAUSE:**

1. **Identify API changes** - Framework versions update their APIs
2. **Update adapter code** - Fix imports, method signatures, type changes
3. **Add missing features** - Enable required features in Cargo.toml dependencies
4. **Fix compilation errors** - Address each error systematically
5. **Test thoroughly** - Ensure adapters work with new framework versions

### Framework Update Process
When updating framework versions:

1. **Update Cargo.toml** with new version numbers
2. **Run `cargo check --features <framework>`** for each adapter
3. **Fix compilation errors** by updating adapter implementations
4. **Common issues to fix:**
   - Import changes (modules moved/renamed)
   - Method signature changes (parameters added/removed/changed)
   - Type changes (new wrapper types, different generics)
   - Feature requirements (missing features in Cargo.toml)
   - Async/await changes (functions became async or sync)

### Example Fixes Applied
- **Actix-Web 4.9**: Fixed `web::options()` removal, updated response handling
- **Warp 0.4**: Added `server` feature, fixed HeaderMap imports
- **Auth-Framework 0.4.2**: Updated for stable Rust toolchain compatibility

### Implementation Philosophy
- **Adapters are complete** - Don't assume they need to be rewritten
- **Framework APIs change** - The issue is usually API compatibility, not logic
- **Fix, don't disable** - Maintain functionality across all supported frameworks
- **Test extensively** - Every adapter should compile and pass tests

## Next Steps
- Expand middleware ecosystem
- Performance benchmarking optimization
- Production-ready features enhancement
- Cross-platform testing expansion
- Multi-language SDK development

Remember: This project aims to become THE web server abstraction solution everyone uses. Make every decision based on what creates the best, most complete solution, not what's quickest or easiest.
