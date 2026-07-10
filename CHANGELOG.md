# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] — 

Privacy on the output side: PII redaction for tool results.

### Added
- **Rampart (Swift)** — a zero-dependency, deterministic PII redactor. `Rampart.redact`
  replaces structured personal data — emails, phones, Luhn-valid credit cards,
  structurally-valid US SSNs, validated IPv4/IPv6, IBANs — with typed, reversible
  placeholders (`[EMAIL_1]`), so a model (especially a remote one) reasons over
  structure instead of secrets. Stable per-value tokens, a PII-safe `summary`
  (labels + counts only), a `keep` set for detect-but-retain classes, and
  `rehydrate` for the redact-outbound / restore-inbound round trip. Names and
  addresses need a NER model and stay in the host app; this is the portable floor.
  Approach inspired by National Design Studio's Rampart (CC BY 4.0); original MIT
  reimplementation.
- **ToolGuard output redaction** — `ToolGuardConfig.redactOutputPII` (with
  `keepPIIEntities`) runs Rampart on a tool's output before it's scanned and wrapped,
  so personal data never survives into the model context. `ToolOutputAssessment`
  gains `piiRedactions` + `piiSummary`. 14 tests.

## [0.4.0] — 

Agents and evasion-resistance release. Detection at parity across the three
languages (71 Python / 69 TypeScript / 69 Swift detection tests); ToolGuard
adds 18 Swift tests on top.

### Added
- **ToolGuard (Swift)** — tool-calling safeguards for agents: Bulwark's new
  second purpose beyond summarization. Guards the three choke points of an
  agent loop: tool **arguments** (`checkCall`: exfiltration-URL heuristics —
  length + opaque-token, embedded credentials, disallowed schemes, syntactic
  private/local-host blocking, invisible-Unicode smuggling, injection-style
  text), tool **outputs** (`registerOutput`: detector scan + nonce-delimited
  untrusted-data wrapping), and the **loop** itself (sliding-window rate limit,
  identical-call loop detection, and session TAINT: once injected content is
  seen in an output, calls above `readOnly` are blocked/flagged until
  `clearTaint()`). New `ToolRisk` levels (`readOnly`/`navigate`/`write`/
  `destructive`), `ToolGuardConfig`, and a `tool` finding stage. 18 tests,
  including the full contained escalation chain. Python and TypeScript ports
  planned.
- **Leetspeak folding** (`fold_leet`) — letters disguised as look-alike digits or
  symbols (`1gn0r3 4ll pr3v10us`, `@dmin`, `$ystem`) are mapped back to ASCII on
  the detection copy before signatures run. Composed with confusable folding via
  `fold_detection`; model-facing text and legitimate numerals are untouched.
- **Six more languages** — injection signatures for Korean, Arabic, Hindi,
  Turkish, Dutch, and Polish, bringing detection to **15 languages** (70
  signatures total). The multilingual corpus enforces recall and zero false
  positives on benign foreign text for each.
- **New English signatures** — enable developer/god mode, hypothetical/fictional
  jailbreak framing, shell/code execution requests, context-reset/clear, cancel
  the real task, and markdown links carrying a data-bearing query string.
- **Reference-style link exfiltration** — output validation now catches and
  redacts reference-style markdown definitions (`[id]: https://…`), not just
  inline `[text](url)` links.

### Changed
- Dev tooling: upgraded the TypeScript test runner to `vitest@4` (clears all
  transitive `esbuild`/`vite` advisories) and moved the CI matrix to Node
  20/22/24 (Node 18 is end-of-life). The published package remains
  zero-dependency; the library's `engines.node` is unchanged at `>=18`.

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
