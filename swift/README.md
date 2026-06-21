# 🛡️ Bulwark (Swift)

**An open-source safeguard against prompt injection in AI summarization.**

Summarizing untrusted content (web pages, emails, PDFs, search results) with an
LLM is dangerous: hidden instructions in that content can hijack the model.
Bulwark wraps **any** model in five layers of defense — sanitize, detect,
spotlight, harden, validate — so the content gets summarized and the attack
inside it doesn't.

Pure Swift + Foundation, no third-party dependencies. Works on macOS, iOS,
tvOS, watchOS (and Linux). Full docs, threat model, and architecture:
https://github.com/Myrhex-x/bulwark

## Install (Swift Package Manager)

In `Package.swift`:

```swift
.package(url: "https://github.com/Myrhex-x/bulwark.git", from: "0.3.0")
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
