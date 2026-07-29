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
import { foldDetection, sanitize } from "./sanitize.js";
import type { DetectResult } from "./types.js";

export const VERSION = "1.1.0";

export {
  Bulwark,
  balancedConfig,
  strictConfig,
  paranoidConfig,
  type BulwarkConfig,
  type PreparedRequest,
} from "./guard.js";

export { sanitize, stripInvisible, stripHtml, normalize, looksLikeHtml, foldConfusables, foldLeet, foldDetection } from "./sanitize.js";
export { detect, matchSignatures, heuristicFindings, scoreFindings, bucket } from "./detect.js";
export { spotlight, delimit, datamark, encodeBase64, makeNonce, DEFAULT_MARKER } from "./spotlight.js";
export { buildMessages, makeCanary } from "./prompt.js";
export { validateOutput } from "./validate.js";
export { SIGNATURES, type Signature } from "./patterns.js";
export {
  analyze as analyzeUrl,
  classifyHost,
  isPrivateHost,
  isMetadataHost,
  parseIpv4,
  ipv4ToString,
  splitUrl,
  type AnalyzeOptions,
  type HostKind,
  type SplitURL,
  type URLAssessment,
} from "./urlcheck.js";
export {
  checkGrounding,
  extractHosts,
  extractEmails,
  contentWords,
  type GroundingReport,
  type GroundingOptions,
} from "./grounding.js";
export {
  profile as contextProfile,
  apply as applyContext,
  signalsFor,
  discountFor,
  MIN_DISCOUNT,
  ContextProfile,
  type Span,
} from "./context.js";
export * from "./types.js";

/** Sanitize then detect injection in `text` — convenience wrapper, no model call.
 * Detection runs on a folded copy so leetspeak ("1gn0r3") and homoglyph
 * disguises are caught. */
export function scan(text: string, threshold = 0.5): DetectResult {
  const s = sanitize(text);
  return detect(s.text, {
    threshold,
    extraFindings: s.findings,
    alsoScan: foldDetection(s.text),
    // The raw text, deliberately: channels such as zero-width bit strings are
    // removed by sanitization precisely because they are invisible, so decoding
    // the sanitized copy would find nothing.
    alsoDecode: text,
  });
}

// --- 1.0.0 layers ---------------------------------------------------------

export {
  unwrap as decodeLayers,
  describe as describeDecodedLayers,
  looksLikeText,
  rot13,
  reverse,
  type DecodedLayer,
  type UnwrapOptions,
} from "./decode.js";

export {
  analyzeSegments,
  neutralize,
  Segment,
  SegmentReport,
  DEFAULT_PLACEHOLDER,
} from "./segment.js";

export { Session, type SessionVerdict, type SessionDocument } from "./session.js";

export {
  makeTripwire,
  plant as plantTripwire,
  check as checkTripwire,
  redact as redactTripwire,
  type Tripwire,
} from "./tripwire.js";

export {
  redact as redactPII,
  rehydrate as rehydratePII,
  luhnValid,
  validSSN,
  ibanValid,
  jwtValid,
  type Entity as PIIEntity,
  type Redaction as PIIRedaction,
} from "./rampart.js";

export { decodedFindings } from "./detect.js";
