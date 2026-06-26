# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 

Evasion-resistant detection, runtime-extensible signatures, and a labeled eval.
All three languages stay at parity (74 Python / 72 TypeScript / 70 Swift tests),
produce identical verdicts, and run in CI.

### Added
- **Custom signatures** (`make_signature` / `makeSignature`) — register
  org-specific patterns via `BulwarkConfig(extra_signatures=[...])` /
  `new Bulwark({ extraSignatures })` / `BulwarkConfig(extraSignatures:)` without
  forking the database. They ride the same de-obfuscation and Base64 passes as
  the built-ins.
- **Evaluation harness** (`eval/`) — a labeled 82-sample corpus and a runner
  (`python eval/run_eval.py`) reporting recall / precision / F1 with a per-group
  breakdown and an optional CI gate. Current: recall 0.92, precision 1.00.
- **Leetspeak folding** (`fold_leet`) — digit/symbol letter substitutions
  (`1gn0re`, `pr0mpt`, `reve4l`, `$ystem`) are folded back to letters on the
  detection copy, so the trigger word is matched. Only runs inside word-like
  tokens, so standalone numbers, prices, and versions are left alone.
- **Spaced-letter collapse** (`collapse_spaced_letters`) — a trigger word smeared
  across single characters (`i g n o r e`, `i.g.n.o.r.e`, `d-i-s-r-e-g-a-r-d`) is
  rejoined for detection. Word boundaries are preserved and short acronyms
  (`U.S.A`) are left intact.
- **Base64 payload decoding** (`decode_base64_payloads`) — embedded Base64 blobs
  that decode to printable text are scanned with the full signature set, so an
  instruction smuggled as `<base64>` is caught. Blobs that decode to binary
  (keys, hashes) are skipped, so they don't create noise. Toggle with the new
  `decode_base64` config flag.
- A dedicated keyword-evasion test corpus in each language.

### Changed
- The detector's second pass now runs on a fully de-obfuscated copy
  (`fold_for_detection`: spaced-out letters joined, then homoglyphs and leetspeak
  folded), superseding the confusable-only fold. The model-facing text is still
  never modified — every transform is detection-only.

### Fixed
- **Boundary signature** `bnd.close_wrapper` now also matches Bulwark's own
  default delimiter tag (`</untrusted_content>`), not just `</untrusted>`.
- Corrected the stale `bulwark-ai` package name in the TypeScript entry-point
  docstring to `bulwark-guard`.
- Pointed all project URLs (CI badges, package metadata, SwiftPM install line) at
  the canonical `github.com/Searxly/bulwark` repository.
- Bumped TypeScript dev tooling (`vitest` 1 → 3) to clear all `npm audit`
  advisories; the runtime core remains zero-dependency.

## [0.3.0] — 

Second security review. All three languages at parity (59 Python / 58 TypeScript
/ 57 Swift tests). See [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).

### Added
- **Multilingual detection** — injection signatures for French, Spanish, German,
  Portuguese, Italian, Russian, Chinese, and Japanese (58 signatures total),
  with a multilingual corpus enforcing recall and zero false positives on benign
  foreign text.
- **Two-pass detection** — signatures run on the un-folded text (multilingual /
  non-Latin) *and* a confusable-folded copy (homoglyph English), merged + deduped.
- **Prompt-fingerprint leak detection** — output validation flags verbatim
  fragments of the system prompt even when the canary line was stripped.
- **Encoded-output flag** — long Base64 blobs in the output are flagged as
  possible encoded exfiltration.

### Removed
- `CODE_OF_CONDUCT.md`.

## [0.2.0] — 

Security-review hardening + a **Swift** implementation. See
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md). All three languages are at
parity (53 Python / 52 TypeScript / 51 Swift tests, identical verdicts).

### Added
- **Swift package** (`Bulwark`, SwiftPM, Foundation-only) — full five-layer
  pipeline mirroring Python/TypeScript, with an async `summarize` API.
- **Cross-script homoglyph folding** (`fold_confusables`): Cyrillic/Greek
  look-alikes are mapped to ASCII for the detection copy, so disguises like
  `іgnоrе аll рrеvіоus іnstruсtіоns` are caught. Model-facing text is untouched.
- **Stack-based HTML extraction** that correctly drops nested hidden subtrees,
  `<script>`/`<style>`/`<noscript>`/`<template>`, comments, `hidden`, and
  `aria-hidden` (stdlib `html.parser` in Python; a tokenizer in TS).
- **Output normalization before validation** — invisibles stripped + NFKC — so a
  zero-width-split canary or exfiltration URL can't evade the checks.
- Expanded output exfiltration detection: HTML `<img>`, autolinks, and raw URLs
  with a data-bearing query string.
- 13 new injection signatures (now **49** across 8 categories): authority/
  precedence overrides, disable-safety, identity reassignment, forged
  `Human:`/`User:` turns, "repeat everything above", email exfiltration, and more.
- `max_content_chars` input cap (default 200k).
- A red-team corpus test asserting 100% recall / 0% false positives.

### Changed
- **Trust semantics:** `safe` now reflects *output* safety only. New
  `injection_detected` flag and `status` (`SAFE`/`CONTAINED`/`UNSAFE`/`BLOCKED`)
  distinguish "a contained attack" from "an unsafe result". A detected-but-
  contained injection is now `safe=True`, `status="CONTAINED"`.

## [0.1.0] — 

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
