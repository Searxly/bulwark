# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-06-21

Initial release. Python and TypeScript implementations at parity.

### Added
- Five-stage defense pipeline: sanitize → detect → spotlight → harden → validate.
- **Sanitization**: strips Unicode Tag (ASCII smuggling), bidi/Trojan-Source,
  zero-width, variation-selector, and control characters; removes HTML
  comments/scripts/hidden elements; NFKC normalization.
- **Detection**: 35+ injection signatures across 8 categories + structural
  heuristics, combined with a noisy-OR risk score.
- **Spotlighting**: random-nonce delimiting, data-marking, and base64 modes.
- **Hardened prompt** with a per-request canary token and sandwich reminder.
- **Output validation**: canary/nonce leak detection, markdown image/link
  exfiltration stripping, compliance-tell flagging.
- `Bulwark` orchestrator with `summarize` / `scan` / `prepare` / `finalize`.
- `balanced`, `strict`, and `paranoid` configuration presets.
- Optional OpenAI and Anthropic backends (Python).
- CLI: `python -m bulwark` for shell-based scanning.
- Full test suites (37 tests each) and CI for both languages.
- MIT licensed.
