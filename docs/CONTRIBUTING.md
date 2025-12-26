# Contributing to Dynamo

## Development Setup

### Prerequisites

- Node.js 18+
- Rust 1.75+
- Docker and Docker Compose
- Git

### Local Environment

1. Clone repository:
```bash
git clone https://github.com/dynamo/dynamo.git
cd dynamo
```

2. Install dependencies:
```bash
npm install
cd packages/rust-analyzer && cargo build
```

3. Start development services:
```bash
docker-compose up postgres redis
```

4. Run services:
```bash
# Terminal 1: Rust analyzer
cd packages/rust-analyzer
cargo run

# Terminal 2: API server
cd packages/api-server
npm run dev

# Terminal 3: Frontend
cd packages/frontend
npm run dev
```

## Code Standards

### TypeScript

- Use TypeScript strict mode
- Prefer functional components with hooks
- Use async/await over promises
- Follow ESLint configuration
- Maximum line length: 100 characters

Example:
```typescript
export async function analyzeTransaction(
  signature: string
): Promise<AnalysisResult> {
  const result = await client.analyze(signature);
  return result;
}
```

### Rust

- Follow Rust API guidelines
- Use `clippy` for linting
- Use `rustfmt` for formatting
- Prefer `Result<T, E>` over panics
- Document public APIs

Example:
```rust
/// Analyzes a transaction for security exploits
pub async fn analyze_transaction(
    &self,
    request: AnalysisRequest,
) -> Result<AnalysisResponse> {
    // Implementation
}
```

## Testing

### Unit Tests

TypeScript:
```bash
npm test
```

Rust:
```bash
cargo test
```

### Integration Tests

```bash
npm run test:integration
```

### Test Coverage

Minimum coverage requirements:
- Critical paths: 90%
- Overall: 70%

## Pull Request Process

1. Fork repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push branch: `git push origin feature/amazing-feature`
5. Open pull request

### PR Requirements

- Pass all CI checks
- Include tests for new features
- Update documentation
- Follow commit message conventions
- Request review from maintainers

### Commit Messages

Format:
```
type(scope): subject

body

footer
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Testing
- `chore`: Maintenance

Example:
```
feat(analyzer): add flash loan detection

Implement detection for flash loan attacks by analyzing
balance changes within single transactions.

Closes #123
```

## Documentation

Update relevant documentation:
- README.md for user-facing changes
- API_REFERENCE.md for API changes
- ARCHITECTURE.md for system changes
- Inline code comments

## Release Process

1. Update version in package.json
2. Update CHANGELOG.md
3. Create release tag
4. Build and push Docker images
5. Deploy to staging
6. Run smoke tests
7. Deploy to production

## Code Review

Reviewers check for:
- Correctness
- Performance
- Security implications
- Test coverage
- Documentation
- Code style

## Community

- GitHub Discussions for questions
- GitHub Issues for bugs/features
- Discord for real-time chat

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

