# 🛡️ Bulwark (TypeScript)

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
npm install bulwark-ai
```

## Use

```ts
import { Bulwark } from "bulwark-ai";

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
import { scan } from "bulwark-ai";
if (scan(text).injected) {
  // ...
}
```

## Presets

```ts
import { Bulwark, strictConfig, paranoidConfig } from "bulwark-ai";
new Bulwark(strictConfig());    // delimiting + data-marking, blocks on critical
new Bulwark(paranoidConfig());  // base64 isolation, blocks on high
```

> No prompt-injection defense is perfect. Bulwark applies every robust mitigation
> at once and validates the model's output, but you should still keep your
> summarizer read-only and gate downstream actions. See the threat model.

MIT licensed — free for any use, including commercial.
