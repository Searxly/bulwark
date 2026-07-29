# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] —

The measurement release. Bulwark now grades itself against a labeled corpus,
defends those numbers in CI, and has been through a large adversarial audit
whose confirmed findings are fixed and locked in with regression tests.

**The Python implementation is the reference for everything below. TypeScript
and Swift have not yet received the new detection layers or signatures** — the
new `tools/conformance.py` harness measures that gap rather than assuming it
away, and currently reports 529 divergences across the 888-case corpus. The
previous README claim that the three implementations "produce identical
verdicts" was never tested and is not true today; it has been replaced with the
measured number.

### Measured

- **Shared ground-truth corpus** (`corpus/`) — 888 labeled documents: 539
  attacks across 10 classes and 41 languages, 349 benign controls across 81
  genres, including a deliberate false-positive minefield of security writing,
  LLM API docs, changelogs, recipes and legal boilerplate. Written independently
  of the implementation, so a failing case is a bug report rather than a
  tautology.
- **`tools/bench.py`** — precision, recall, F1 and false-positive rate, broken
  down by attack class, benign genre and language, with the missed attacks and
  false positives listed by id. `--gate` fails CI on any regression, including
  a single previously-caught attack becoming a miss.
- **`tools/conformance.py`** — runs the identical corpus bytes through all three
  implementations and diffs verdict, score, risk and fired signature ids.
- Baseline at 1.0.0: **recall 0.388, precision 0.867, F1 0.536, FPR 0.092**
  (0.029 excluding cases marked deliberately borderline). Read recall as "share
  of hard, realistic attacks caught" — the corpus is adversarially weighted on
  purpose, not a sample of ordinary traffic.

### Added — new defensive layers (Python)

- **`decode`** — recursively decodes encoded payloads and re-scans each layer,
  keeping a provenance chain (`base64 → rot13 → "ignore all previous…"`).
  Covers Base64/Base64url, hex, percent-encoding, numeric HTML entities, unicode
  escapes, decimal char codes, ROT13, reversal, letter-spacing, Morse and
  zero-width bit strings. Runs on the raw content, before sanitization removes
  the invisible channels. Depth, layer count and total decoded size are capped.
- **`grounding`** — checks the reply against the source. Every host, URL and
  email address in a summary must occur in the document it summarized; a novel
  one cannot have come from summarizing and is reported `critical`. A weaker
  lexical-overlap measure backs it up, skippable for cross-language summaries.
- **`context`** — tells a document that *performs* an attack from one that
  *discusses* one, by combining quoting constructs with meta-discourse. Discount
  deepens only as independent signals stack, and is floored well above zero, so
  it can never become a bypass.
- **`segment`** — scores each passage separately and reports a contamination
  ratio. `neutralize()` excises only the poisoned passages, so one hostile
  paragraph no longer costs the whole article.
- **`tripwire`** — plants a harmless positive control in the content. If the
  model echoes the code, it provably followed an instruction from the data.
  Opt-in; on in `paranoid`.
- **`session`** — catches a payload split across several sources so that no
  single document is injected but their concatenation is.
- **`urlcheck`** — canonicalizes hosts the way the network stack does (the full
  `inet_aton` grammar, IPv6, IPv4-mapped), then classifies: private ranges,
  cloud metadata endpoints, userinfo tricks, punycode and mixed-script
  homographs, and opaque payloads in a query, path, fragment or subdomain.
- **`rampart`** (Python port) — deterministic redaction of sensitive values,
  now covering 12 classes including API keys, JWTs, private keys, crypto
  addresses, MAC addresses and national IDs. IBANs are mod-97 validated.
- **`toolguard`** (Python port) — the agentic-loop safeguards, with recursive
  argument traversal, `urlcheck`-backed URL analysis, thread safety, and a new
  **echo check**: a call aimed at a host named by content that scanned as
  injected is refused outright, and that memory survives clearing the taint.

### Fixed — from the adversarial audit

- **A single line break defeated the flagship signatures.** Bounded spans like
  `.{0,40}?` do not cross a newline in any of the three regex engines, so
  ordinary 72-column wrapping dropped "ignore all previous instructions" from
  0.86 to 0.00. Detection now also runs over a flattened view that collapses
  whitespace and rejoins hyphenated line breaks, carrying an offset map so
  spans still point at the original text. (DOTALL would have been the wrong
  fix — it lets a bounded span pair up words in different paragraphs.)
- Intra-word hyphenation (`dis-\nregard`), stacked combining diacritics, Hangul
  fillers, interlinear annotation controls and the combining grapheme joiner all
  defeated every signature; each is now handled.
- **`^\s*` under MULTILINE was quadratic** — 200KB of newlines wedged the
  scanner. Three signatures were affected.
- A single emoji variation selector produced a `high` "data smuggling" finding,
  which the severity rule turned into `injected=true` for any document
  containing an emoji.
- The hidden-CSS pattern matched *any* opacity and font-size value, so
  `opacity:0.95` silently deleted visible article text.
- XHTML self-closing syntax unbalanced the HTML skip depth, leaking hidden
  subtrees to the model.
- Over-broad signatures that scored ordinary documentation as an attack — every
  markdown image, every `curl https://`, every mention of "jailbreak", every
  "run the script" and "drop the table" — are now paired: a low-weight broad
  member keeps coverage, a high-weight specific member carries the confidence.
- **Output validation** — covered only `<img>`; now covers every element that
  fetches, plus CSS `url()`, reference-style links and images, autolinks, bare
  domains and non-HTTP schemes. Data in a path, fragment or subdomain counts
  like data in a query string. The canary check is no longer a case-sensitive
  substring match, so a spaced-out or emphasis-split echo still counts. All
  seven system-prompt rules are fingerprinted, not three. A confirmed
  exfiltration channel now marks the summary unsafe instead of reporting SAFE.
  Detection runs before redaction, so a rewrite can no longer erase the evidence
  of a finding it had already seen.

### Fixed — Swift

- **`Rampart.rehydrate` was not injective.** An attacker who planted `[EMAIL_1]`
  in a page and got the model to echo it made a rehydrating host substitute a
  *real* address into text the attacker could read. Placeholders now carry a
  per-redaction random nonce, so a planted token stays literal.
- **`ToolGuard.isPrivateHost` missed every non-canonical loopback spelling** —
  `0177.0.0.1`, `0x7f.0.0.1`, `2130706433`, `127.1`, `localhost.`. Hosts are now
  canonicalized through the full `inet_aton` grammar, and cloud metadata
  endpoints are called out separately.
- `foldConfusables` and `foldLeet` iterated grapheme clusters, so a single
  combining mark defeated the whole homoglyph and leetspeak fold. Both now
  iterate unicode scalars.
- `keepPIIEntities` was applied after overlap resolution and honoured neither
  way; placeholders were numbered right-to-left, so `[EMAIL_1]` was the *last*
  email in the document.

### Known gaps

- TypeScript and Swift do not yet have the new layers, signatures or fixes
  above. `tools/conformance.py` reports the gap precisely.
- The remaining audit findings specific to the TypeScript and Swift sanitizers
  (entity coverage, tag scanning, attribute matching, `\b`/`\w` ASCII semantics)
  are unfixed.

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
