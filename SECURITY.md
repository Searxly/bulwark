# Security policy

Bulwark is a security tool, so we take its own correctness seriously.

## Reporting a vulnerability

If you find a way to bypass Bulwark's defenses, or a bug in Bulwark that could
weaken an application that relies on it, please report it **privately** first:

- Open a [GitHub Security Advisory](https://github.com/Myrhex-x/bulwark/security/advisories/new)
  (preferred), or
- Email the maintainer listed on the GitHub profile.

Please include a minimal reproduction (an input + the bypass) where possible.
We aim to acknowledge reports within a few days.

## Scope

In scope:
- Sanitization bypasses (hidden text that survives `sanitize` — invisible
  Unicode, homoglyphs, nested hidden HTML).
- Detection evasion that an added signature could reasonably catch, including
  payloads in languages Bulwark does not yet cover.
- Output-validation bypasses (canary, prompt-fingerprint, nonce, or
  exfiltration that slips through).
- Boundary-breakout against the nonce delimiter.

Out of scope (known limitations, see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)):
- A novel prose jailbreak that a *specific* model obeys despite the hardened
  prompt. Input-side libraries cannot fully prevent this; that is why Bulwark
  also validates output and recommends least-privilege isolation. Still, please
  do share interesting payloads — they make great regression tests.

## A note for users

No prompt-injection defense is perfect. Use Bulwark as **one layer**:
keep your summarizer read-only (no tools/network), gate any downstream action
behind explicit user confirmation, and log `result.report` for auditing.
