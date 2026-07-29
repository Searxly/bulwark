/**
 * Conformance driver — TypeScript.
 *
 * Reads the merged corpus JSONL on stdin, writes one result object per line.
 * The shape must match tools/drivers/scan_py.py exactly; tools/conformance.py
 * diffs the two.
 *
 *   npx tsx tools/drivers/scan_ts.ts < corpus/corpus.jsonl
 */

import { detect } from "../../typescript/src/detect.js";
import { foldDetection, sanitize } from "../../typescript/src/sanitize.js";

const THRESHOLD = 0.5;

function resultFor(text: string) {
  const san = sanitize(text);
  const det = detect(san.text, {
    threshold: THRESHOLD,
    extraFindings: san.findings,
    alsoScan: foldDetection(san.text),
    alsoDecode: text,
  });
  const patterns = [...new Set(det.findings.map((f) => f.patternId).filter(Boolean))].sort();
  const categories = [...new Set(det.findings.map((f) => f.category))].sort();
  return {
    injected: det.injected,
    score: Math.round(det.score * 1e4) / 1e4,
    risk: det.risk,
    patterns,
    categories,
    sanitized_len: [...san.text].length,
  };
}

// Stable key order so the two drivers' output can be compared as raw text too.
function stableStringify(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  return JSON.stringify(Object.fromEntries(keys.map((k) => [k, obj[k]])));
}

async function main() {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  const input = Buffer.concat(chunks).toString("utf8");

  const out: string[] = [];
  for (const line of input.split("\n")) {
    if (!line.trim()) continue;
    const testCase = JSON.parse(line);
    out.push(stableStringify({ id: testCase.id, ...resultFor(testCase.text) }));
  }
  process.stdout.write(out.join("\n") + (out.length ? "\n" : ""));
}

main();
