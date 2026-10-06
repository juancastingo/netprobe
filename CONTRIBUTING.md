# Contributing to NetProbe

Thank you for your interest in improving NetProbe!

## Code of Conduct
Please be polite, constructive, and respectful to fellow contributors.

## How to Contribute

1. **Reporting Bugs**:
   - Search existing issues to ensure the bug hasn't already been reported.
   - Include OS version, the command executed, output (with sensitive domains/IPs redacted if necessary), and error details.

2. **Proposing Enhancements**:
   - Open an issue describing the proposed feature and why it would be beneficial to users.

3. **Submitting Pull Requests**:
   - Fork the repository and create a branch from `main`.
   - Make sure your changes compile cleanly without warnings:
     ```bash
     cargo fmt --check
     cargo clippy --all-targets -- -D warnings
     cargo test
     ```
   - Add unit or integration tests covering your new feature or bugfix.
   - Submit your pull request with a clear description of the change.

## Development Setup

```bash
git clone https://github.com/juancastingo/netprobe.git
cd netprobe
cargo test
cargo run -- https://example.com
```
