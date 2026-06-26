/**
 * Bulwark — an open-source safeguard against prompt injection in AI summarization.
 *
 *   import { Bulwark } from "bulwark-guard";
 *
 *   const guard = new Bulwark();
 *   const result = await guard.summarize(untrustedWebPage, myModel); // myModel(messages) => string
 *   console.log(result.summary);  // cleaned, validated summary (or null if blocked)
 *   console.log(result.report);   // human-readable explanation
 *
 * Just want detection, no model?
 *
 *   import { scan } from "bulwark-guard";
 *   if (scan(text).injected) { ... }
 */

import { detect } from "./detect.js";
import type { Signature } from "./patterns.js";
import { foldForDetection, sanitize } from "./sanitize.js";
import type { DetectResult } from "./types.js";

export const VERSION = "0.4.0";

export {
  Bulwark,
  balancedConfig,
  strictConfig,
  paranoidConfig,
  type BulwarkConfig,
  type PreparedRequest,
} from "./guard.js";

export {
  sanitize,
  stripInvisible,
  stripHtml,
  normalize,
  looksLikeHtml,
  foldConfusables,
  foldLeet,
  collapseSpacedLetters,
  foldForDetection,
} from "./sanitize.js";
export { detect, matchSignatures, heuristicFindings, scoreFindings, bucket, decodeBase64Payloads } from "./detect.js";
export { spotlight, delimit, datamark, encodeBase64, makeNonce, DEFAULT_MARKER } from "./spotlight.js";
export { buildMessages, makeCanary } from "./prompt.js";
export { validateOutput } from "./validate.js";
export { SIGNATURES, makeSignature, type Signature } from "./patterns.js";
export * from "./types.js";

/** Sanitize then detect injection in `text` — convenience wrapper, no model call.
 * Detection runs on a de-obfuscated copy (spaced-out letters joined, homoglyphs
 * and leetspeak folded) and decodes embedded Base64 payloads, so the common
 * keyword-evasion tricks are caught. */
export function scan(text: string, threshold = 0.5, extraSignatures?: readonly Signature[]): DetectResult {
  const s = sanitize(text);
  return detect(s.text, { threshold, extraFindings: s.findings, alsoScan: foldForDetection(s.text), extraSignatures });
}
