# Contributing to Bulwark

Thanks for helping make AI summarization safer! Contributions of all sizes are
welcome — especially **new injection signatures** and **red-team test cases**.

## Ground rules

- Keep the Python and TypeScript implementations **in sync**. A change to
  signatures, scoring, prompts, or behaviour should land in both, with matching
  tests.
- The **core stays dependency-free.** Optional integrations (model SDKs, HTML
  parsers) go behind optional extras / peer deps.
- Every behaviour change ships with a test.

## Adding an injection signature

1. **Python:** add a `_sig(...)` entry in
   [`python/src/bulwark/patterns.py`](python/src/bulwark/patterns.py).
2. **TypeScript:** add the matching `sig(...)` entry in
   [`typescript/src/patterns.ts`](typescript/src/patterns.ts) — same `id`,
   `category`, `severity`, `weight`, and pattern.
3. Add a positive test (it fires on the attack) and, ideally, a negative test
   (it does *not* fire on benign lookalike text). Tune the `weight` so a single
   benign false-positive can't push a normal page over the threshold.

## Running the tests

**Python** (no dependencies required):

```bash
cd python
python run_tests.py          # stdlib runner
# or, with pytest installed:
pip install -e ".[dev]" && pytest
```

**TypeScript:**

```bash
cd typescript
npm install
npm run typecheck
npm test
```

CI runs both suites on every PR (see [`.github/workflows`](.github/workflows)).

## Style

- Python: `ruff` + `mypy` (configs in `pyproject.toml`). 120-col lines.
- TypeScript: `strict` mode. 1:1 port of the Python logic where applicable.
- Prefer clarity over cleverness — this is security code people need to audit.

## Reporting bypasses

Found a way past the defenses? See [SECURITY.md](SECURITY.md) — report bypasses
privately first, then we turn them into regression tests.
