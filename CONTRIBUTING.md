# Contributing to VibeGuard

Thank you for your interest in contributing to VibeGuard! Whether you're
filing a bug report, suggesting a feature, improving documentation, writing
code, or sharing `.vgrules` rule lists — every contribution is welcome.

## Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.**

Please use [GitHub Security Advisories](https://github.com/inkdust2021/VibeGuard/security/advisories/new)
to report security issues privately. This ensures vulnerabilities are handled
responsibly before public disclosure.

Ask yourself:

- Can I access or modify data that should be protected?
- Can I bypass the proxy's redaction pipeline?

If the answer is yes, it's likely a security issue — please report it privately.

## How to Report a Bug

Open a [GitHub Issue](https://github.com/inkdust2021/VibeGuard/issues/new) and
include:

1. **VibeGuard version** — run `vibeguard --version` or check the binary name
2. **OS and architecture** — e.g. macOS arm64, Ubuntu 22.04 amd64
3. **Steps to reproduce** — what you did, what config you used
4. **Expected behavior** — what you thought would happen
5. **Actual behavior** — what happened instead (logs, error messages, screenshots)

The more detail you provide, the faster we can help.

## How to Suggest a Feature

We'd love to hear your ideas! Please open a GitHub Issue and describe:

- **The problem** you're trying to solve
- **Your proposed solution** and why it fits VibeGuard's scope
- **Alternatives** you've considered

For larger features, please open an issue for discussion **before** writing
code. This helps avoid wasted effort if the feature doesn't align with the
project's direction.

## Your First Contribution

New to VibeGuard? Look for issues labeled
[`good first issue`](https://github.com/inkdust2021/VibeGuard/labels/good%20first%20issue)
— these are small, well-scoped tasks ideal for getting familiar with the
codebase.

Never contributed to open source before? Check out
[How to Contribute to an Open Source Project on GitHub](https://egghead.io/courses/how-to-contribute-to-an-open-source-project-on-github).

## Development Setup

### Prerequisites

- **Go 1.24+** ([download](https://go.dev/dl/))
- **Git**

### Build and Run

```bash
git clone https://github.com/inkdust2021/VibeGuard.git
cd VibeGuard
go build -o vibeguard ./cmd/vibeguard
./vibeguard
```

### Run Tests

```bash
go test ./...
```

### Project Structure

```
cmd/vibeguard/       — entry point
internal/proxy/      — MITM proxy core
internal/redact/     — redaction engine
internal/restore/    — response restoration
internal/pii_next/   — PII detection pipeline
  ├── keywords/      — keyword matching (Aho-Corasick)
  ├── rulelist/      — .vgrules rule list engine
  └── ner/           — NER integration (external Presidio)
internal/admin/      — admin UI and API
internal/config/     — configuration management
internal/session/    — session store (TTL + WAL)
internal/rulelists/  — rule list subscriptions
```

## Pull Request Process

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. **Make your changes** — keep the scope focused; one PR per feature or fix.
3. **Add or update tests** if your change affects behavior.
4. **Run tests** to make sure nothing is broken:
   ```bash
   go test ./...
   ```
5. **Push** your branch and open a Pull Request against `main`.
6. A **maintainer will review** your PR. Please respond to feedback within
   two weeks, or the PR may be closed.

### What we look for in code review

- Correctness and test coverage
- No security regressions (VibeGuard handles sensitive data — be careful)
- Consistent style with the existing codebase
- Focused scope — avoid unrelated changes in the same PR

## Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add IPv6 address detection
fix: prevent false positive on short phone numbers
docs: update rule list format documentation
chore: upgrade Go toolchain to 1.24.3
refactor: simplify Aho-Corasick matcher
test: add coverage for WAL restore
```

Use the imperative mood ("add", not "added" or "adds").

## Contributing Rule Lists

VibeGuard uses `.vgrules` files for pattern-based PII detection. Community
rule lists are a great way to contribute without writing Go code!

To share your rule list with the community, submit a PR adding your
subscription URL to **[docs/RULE_LISTS.md](docs/RULE_LISTS.md)**.

For rule syntax and examples, see
[`docs/rule_lists.sample.vgrules`](docs/rule_lists.sample.vgrules).

### Tips for good rule lists

- Test your rules locally before submitting — upload via Admin UI (`#/rule_lists`)
  and verify against sample data
- Use capturing groups in regex rules so only the sensitive value is redacted
- Include comments explaining what each rule matches
- Prefer precision over recall — fewer false positives is better

## License

By contributing to VibeGuard, you agree that your contributions will be
licensed under the [Apache License 2.0](LICENSE).
