# 🛡️ Bulwark (Swift)

> ### Parity with the reference implementation
>
> Python is Bulwark's reference implementation, and this package is verified
> against it rather than assumed to match. `python3 tools/conformance.py` runs
> the identical corpus bytes through all three implementations and diffs every
> verdict, score, risk bucket and fired signature id across 888 cases. They
> agree on all of them, and CI keeps it that way.
>
> The signature database is generated from the Python one by
> `tools/gen_patterns.py`, so `Sources/Bulwark/Patterns.swift` is a generated
> file — edit the Python source and regenerate.
>
> **Breaking change in 1.0.0**: Rampart placeholders now carry a per-redaction
> nonce — `[EMAIL_1]` became `[EMAIL_1_a7f3]` — and are numbered in reading
> order rather than backwards. If you assert on placeholder strings, match the
> `[LABEL_N_` prefix rather than the whole token. The change closes a real
> exfiltration path: `rehydrate` was not injective, so a placeholder an attacker
> planted in a source page and got the model to echo would have been replaced
> with a **real** value in text the attacker could read.

**An open-source safeguard against prompt injection in AI summarization.**

Summarizing untrusted content (web pages, emails, PDFs, search results) with an
LLM is dangerous: hidden instructions in that content can hijack the model.
Bulwark wraps **any** model in five layers of defense — sanitize, detect,
spotlight, harden, validate — so the content gets summarized and the attack
inside it doesn't.

Pure Swift + Foundation, no third-party dependencies. Works on macOS, iOS,
tvOS, watchOS (and Linux). Full docs, threat model, and architecture:
https://github.com/Searxly/bulwark

## Install (Swift Package Manager)

In `Package.swift`:

```swift
.package(url: "https://github.com/Searxly/bulwark.git", from: "1.1.0")
```

…and add `"Bulwark"` to your target's dependencies. In Xcode: *File ▸ Add
Package Dependencies…* and paste the URL.

## Use

```swift
import Bulwark

let bulwark = Bulwark()

let result = try await bulwark.summarize(untrustedPage) { messages in
    // Call your model (OpenAI, Anthropic, a local model, anything) and return
    // the reply string. `messages` is [ChatMessage] with .role and .content.
    try await myModel(messages)
}

print(result.summary ?? "[blocked]")   // cleaned, validated summary
print(result.safe)                      // is the returned summary safe to use?
print(result.injectionDetected)         // was an attack present in the input?
print(result.status)                    // .safe / .contained / .unsafe / .blocked
print(result.report)                    // human-readable explanation
```

Detection only (no model):

```swift
import Bulwark

if scan(text).injected {
    // ...
}
```

## Postures

```swift
Bulwark(config: .strict())     // delimiting + data-marking, blocks on critical
Bulwark(config: .paranoid())   // base64 isolation, blocks on high
```

Run your own model with full control via `prepare(_:)` / `finalize(_:prepared:)`.

> No prompt-injection defense is perfect. Bulwark applies every robust mitigation
> at once and validates the model's output, but you should still keep your
> summarizer read-only and gate downstream actions. See the threat model.

MIT licensed — free for any use, including commercial.
