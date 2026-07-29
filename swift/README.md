# 🛡️ Bulwark (Swift)

> ### ⚠️ 1.0.0 status for this language
>
> Swift received all of the 1.0.0 **security fixes** — see below — but not the
> new **detection layers**. This package still has the 0.4.0 detection
> behaviour: the original 70 signatures, no recursive decoding, no output
> grounding, no quoting-context discounting, and not the fix for a single line
> break defeating the instruction-override signatures.
>
> That gap is measured, not estimated. `python3 tools/conformance.py` runs the
> identical corpus bytes through all three implementations and diffs every
> verdict; it currently reports **529 divergences across 888 cases**.
>
> **Breaking change in this release**: Rampart placeholders now carry a
> per-redaction nonce — `[EMAIL_1]` became `[EMAIL_1_a7f3]` — and are numbered
> in reading order rather than backwards. If you assert on placeholder strings,
> match the `[LABEL_N_` prefix rather than the whole token. The change closes a
> real exfiltration path: `rehydrate` was not injective, so a placeholder an
> attacker planted in a source page and got the model to echo would have been
> replaced with a **real** value in text the attacker could read.
>
> Also fixed: `ToolGuard.isPrivateHost` missed every non-canonical loopback
> spelling (`0177.0.0.1`, `0x7f.0.0.1`, `2130706433`, `127.1`, `localhost.`),
> and `foldConfusables`/`foldLeet` iterated grapheme clusters so one combining
> mark defeated the whole fold. New `ToolGuardConfig.blockMetadataHosts`
> (default `true`) is separate from `blockPrivateHosts`, so a host that
> legitimately opens localhost still refuses cloud metadata endpoints.



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
.package(url: "https://github.com/Myrhex-x/bulwark.git", from: "1.0.0")
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
