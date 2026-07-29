# 🛡️ Bulwark (TypeScript)

> ### ⚠️ 1.0.0 status for this language
>
> The repository version is **1.0.0**, but the detection layers and signatures
> added in 1.0.0 landed in the **Python** implementation only. This package
> still has the 0.4.0 detection behaviour: the original 70 signatures, no
> recursive decoding, no output grounding, no quoting-context discounting, and
> none of the audit fixes — including the one where a single line break defeats
> the instruction-override signatures.
>
> That gap is measured, not estimated. `python3 tools/conformance.py` runs the
> identical corpus bytes through all three implementations and diffs every
> verdict; it currently reports **529 divergences across 888 cases**. Bringing
> this port up to parity is the next piece of work, and the harness will say
> when it is done.
>
> Use the Python package if you need the 1.0.0 behaviour today.



**An open-source safeguard against prompt injection in AI summarization.**

Summarizing untrusted content (web pages, emails, PDFs, search results) with an
LLM is dangerous: hidden instructions in that content can hijack the model.
Bulwark wraps **any** model in five layers of defense — sanitize, detect,
spotlight, harden, validate — so the content gets summarized and the attack
inside it doesn't.

Isomorphic (Node 18+, edge, browser), zero runtime dependencies.
Full docs, threat model, and architecture: https://github.com/Myrhex-x/bulwark

## Install

```bash
npm install bulwark-guard
```

## Use

```ts
import { Bulwark } from "bulwark-guard";

const guard = new Bulwark();

const myModel = async (messages) => {
  // call OpenAI / Anthropic / a local model — anything
  return summaryText;
};

const result = await guard.summarize(untrustedPage, myModel);
console.log(result.summary); // cleaned, validated summary (or null if blocked)
console.log(result.report);  // what was caught
```

Detection only (no model):

```ts
import { scan } from "bulwark-guard";
if (scan(text).injected) {
  // ...
}
```

## Presets

```ts
import { Bulwark, strictConfig, paranoidConfig } from "bulwark-guard";
new Bulwark(strictConfig());    // delimiting + data-marking, blocks on critical
new Bulwark(paranoidConfig());  // base64 isolation, blocks on high
```

> No prompt-injection defense is perfect. Bulwark applies every robust mitigation
> at once and validates the model's output, but you should still keep your
> summarizer read-only and gate downstream actions. See the threat model.

MIT licensed — free for any use, including commercial.
