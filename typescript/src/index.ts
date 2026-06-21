/**
 * Bulwark — an open-source safeguard against prompt injection in AI summarization.
 *
 *   import { Bulwark } from "bulwark-ai";
 *
 *   const guard = new Bulwark();
 *   const result = await guard.summarize(untrustedWebPage, myModel); // myModel(messages) => string
 *   console.log(result.summary);  // cleaned, validated summary (or null if blocked)
 *   console.log(result.report);   // human-readable explanation
 *
 * Just want detection, no model?
 *
 *   import { scan } from "bulwark-ai";
 *   if (scan(text).injected) { ... }
 */

import { detect } from "./detect.js";
import { foldConfusables, sanitize } from "./sanitize.js";
import type { DetectResult } from "./types.js";

export const VERSION = "0.3.0";

export {
  Bulwark,
  balancedConfig,
  strictConfig,
  paranoidConfig,
  type BulwarkConfig,
  type PreparedRequest,
} from "./guard.js";

export { sanitize, stripInvisible, stripHtml, normalize, looksLikeHtml, foldConfusables } from "./sanitize.js";
export { detect, matchSignatures, heuristicFindings, scoreFindings, bucket } from "./detect.js";
export { spotlight, delimit, datamark, encodeBase64, makeNonce, DEFAULT_MARKER } from "./spotlight.js";
export { buildMessages, makeCanary } from "./prompt.js";
export { validateOutput } from "./validate.js";
export { SIGNATURES, type Signature } from "./patterns.js";
export * from "./types.js";

/** Sanitize then detect injection in `text` — convenience wrapper, no model call.
 * Detection runs on a confusable-folded copy so homoglyph disguises are caught. */
export function scan(text: string, threshold = 0.5): DetectResult {
  const s = sanitize(text);
  return detect(s.text, { threshold, extraFindings: s.findings, alsoScan: foldConfusables(s.text) });
}
