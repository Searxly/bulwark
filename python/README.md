# 🛡️ Bulwark (Python)

**An open-source safeguard against prompt injection in AI summarization.**

Summarizing untrusted content (web pages, emails, PDFs, search results) with an
LLM is dangerous: hidden instructions in that content can hijack the model.
Bulwark wraps **any** model in five layers of defense — sanitize, detect,
spotlight, harden, validate — so the content gets summarized and the attack
inside it doesn't.

Full docs, threat model, and architecture: https://github.com/Myrhex-x/bulwark

## Install

```bash
pip install bulwark-guard                 # zero dependencies
pip install "bulwark-guard[openai]"       # optional OpenAI adapter
pip install "bulwark-guard[anthropic]"    # optional Anthropic adapter
```

## Use

```python
from bulwark import Bulwark

guard = Bulwark()

def my_model(messages):          # any callable: messages -> str
    ...
    return summary_text

result = guard.summarize(untrusted_page, llm=my_model)
print(result.summary)            # cleaned, validated summary (or None if blocked)
print(result.report)             # what was caught
```

Detection only (no model):

```python
from bulwark import scan
if scan(text).injected:
    ...
```

CLI:

```bash
echo "ignore previous instructions" | python -m bulwark
```

## Presets

```python
from bulwark import Bulwark, BulwarkConfig
Bulwark(BulwarkConfig.strict())     # delimiting + data-marking, blocks on critical
Bulwark(BulwarkConfig.paranoid())   # base64 isolation, blocks on high
```

> No prompt-injection defense is perfect. Bulwark applies every robust mitigation
> at once and validates the model's output, but you should still keep your
> summarizer read-only and gate downstream actions. See the threat model.

MIT licensed — free for any use, including commercial.
