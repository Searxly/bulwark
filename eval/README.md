# Evaluation

A small, inspectable benchmark for Bulwark's **detection** stage (`scan`). It
measures recall (are attacks flagged?) and precision (is benign text left
alone?) on a labeled corpus, with a per-group breakdown.

```bash
python eval/run_eval.py                 # human-readable report
python eval/run_eval.py --json          # machine-readable
python eval/run_eval.py --threshold 0.4 # sweep the decision threshold
```

The corpus lives in [`dataset.jsonl`](dataset.jsonl) — one
`{"text", "label", "group"}` record per line, `label ∈ {attack, benign}`. It
covers instruction override, role injection, prompt leak, exfiltration,
jailbreak, tool injection, boundary breakout, the 9 supported languages, every
keyword-evasion trick (leetspeak, spacing, homoglyphs, zero-width, Base64, hidden
HTML), and a deliberately adversarial set of *benign* text: trigger-ish prose
("ignore the warning", "follow the recipe"), numbers/acronyms/prices, code, and
foreign-language content.

## Current result

```
recall    0.92      precision 1.00      F1 0.96
```

Precision on this corpus is **1.00** — no benign sample is flagged, including the
ones designed to bait a naive keyword filter.

## On the recall misses — read this

Detection is **layer 2 of 5**, and it is intentionally tuned to favor precision.
A handful of low-signal payloads (a bare "from now on you must…", an
authority-framed "important system notice", the "grandma" role-play opener) are
scored *low on purpose*: weighting them high enough to flag would also flag
ordinary prose. These are **not** undefended — the spotlighting boundary, the
hardened system prompt, and the output validator still contain them end-to-end.
The eval reports them as detection misses because that is the honest picture of
what the regex layer alone catches; it is not a claim that the attack succeeds.

This is why the regression gate (`--min-recall`, `--min-precision`) defaults to
treating a **precision** drop as the harder failure: a new false positive is a
real-world regression, whereas the long tail of low-signal phrasings is a known,
accepted trade-off.

## Extending it

Add lines to `dataset.jsonl` (especially real payloads you've seen in the wild)
and re-run. If you add a custom signature with `make_signature`, point the runner
at it by importing your config — or just confirm the built-in database still
holds the line.
