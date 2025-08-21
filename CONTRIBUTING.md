# Contributing to Web Server Abstraction

Thank you for your interest in contributing to Web Server Abstraction! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

Please be respectful and considerate of others when contributing to this project. We aim to foster an inclusive and welcoming community.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion for improvement:

1. Check if the issue already exists in the [issue tracker](https://github.com/ciresnave/web-server-abstraction/issues)
2. If not, create a new issue with a clear title and description
3. Include steps to reproduce the issue, if applicable
4. Add relevant tags/labels

### Pull Requests

1. Fork the repository
2. Create a new branch for your changes (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Run the tests to ensure your changes don't break existing functionality
5. Commit your changes with a clear commit message
6. Push your branch to your fork
7. Create a pull request to the main repository

### Coding Guidelines

- Follow the Rust style guidelines and idioms
- Use the Rust formatter (`rustfmt`) before submitting code
- Run clippy (`cargo clippy`) to catch common mistakes
- Write tests for new functionality
- Update documentation as necessary

## Development Setup

1. Clone the repository
2. Install Rust and Cargo
3. Run `cargo build` to build the project
4. Run `cargo test` to run the tests

## Key Areas for Contribution

We welcome contributions in the following areas:

1. **Framework Adapters**: Implementing adapters for different web frameworks
2. **Middleware**: Adding common middleware implementations
3. **Documentation**: Improving docs and examples
4. **Testing**: Adding comprehensive test coverage
5. **Performance**: Benchmarking and optimization

### Adding a New Framework Adapter

1. Create a new module in `src/adapters/`
2. Implement the required methods: `bind`, `run`, `route`, `middleware`
3. Add conversion functions between framework types and our types
4. Add a feature flag in `Cargo.toml`
5. Update the `AdapterType` enum in `core.rs`
6. Add tests and documentation

## License

By contributing to this project, you agree that your contributions will be licensed under the project's dual MIT and Apache 2.0 licenses.
