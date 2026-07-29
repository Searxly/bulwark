/**
 * The high-level orchestrator. Wires sanitize → detect → spotlight → harden →
 * validate into one call. Bring any model: `(messages) => string | Promise<string>`.
 */

import { bucket, detect, scoreFindings } from "./detect.js";
import { buildMessages } from "./prompt.js";
import { DEFAULT_MARKER, spotlight } from "./spotlight.js";
import { foldDetection, sanitize } from "./sanitize.js";
import { makeTripwire, plant as plantTripwire, type Tripwire } from "./tripwire.js";
import { validateOutput } from "./validate.js";
import {
  formatReport,
  severityGte,
  type DetectResult,
  type Finding,
  type GuardResult,
  type LLM,
  type Messages,
  type PromptContext,
  type SanitizeResult,
  type Severity,
  type SpotlightResult,
  type ValidationResult,
} from "./types.js";

export interface BulwarkConfig {
  // sanitize
  stripHtml: boolean | "auto";
  normalizeUnicode: boolean;
  keepEmojiVariation: boolean;
  foldConfusables: boolean;
  /** Hard cap on input size (defence against pathological inputs / cost blowups). */
  maxContentChars: number;
  // detect
  detectionThreshold: number;
  useHeuristics: boolean;
  /** Recursively decode encoded payloads (Base64, hex, percent, entities,
   * ROT13, zero-width bits …) and re-scan each layer. Runs on the raw content,
   * before sanitization strips the invisible channels. */
  decodeEncoded: boolean;
  /** Discount findings that sit inside quoted or code-fenced passages of a
   * document that reads as writing *about* attacks. Precision, not permission:
   * weights drop, findings never disappear. */
  useContext: boolean;
  /** Refuse to call the model when risk reaches this severity (null = never). */
  blockBeforeLlm: Severity | null;
  // spotlight
  spotlightMethods: string[];
  marker: string;
  // prompt
  maxWords: number | null;
  language: string | null;
  extraInstruction: string | null;
  // validate
  redactOutputLinks: boolean;
  redactOutputImages: boolean;
  blockOnOutputLeak: boolean;
  /** Mark the summary unsafe when it carries a high-severity exfiltration
   * channel. Without this a reply containing a confirmed exfiltration URL was
   * still reported SAFE, which is the wrong headline to act on. */
  blockOnExfiltration: boolean;
  /** Check the reply against the source: hosts, URLs and addresses it mentions
   * must appear in the document it was asked to summarize. */
  checkGrounding: boolean;
  /** The vocabulary-overlap half of grounding. Turn it off when the summary is
   * requested in a different language than the source. */
  checkLexicalGrounding: boolean;
  /** Plant a positive control in the content and check whether the model obeyed
   * it. Proof of compliance rather than a symptom — but it *is* an injection
   * attempt, so a correctly-behaving model will note it. Opt-in. */
  tripwire: boolean;
}

export function balancedConfig(): BulwarkConfig {
  return {
    stripHtml: "auto",
    normalizeUnicode: true,
    keepEmojiVariation: false,
    foldConfusables: true,
    maxContentChars: 200_000,
    detectionThreshold: 0.5,
    useHeuristics: true,
    decodeEncoded: true,
    useContext: true,
    blockBeforeLlm: null,
    spotlightMethods: ["delimit"],
    marker: DEFAULT_MARKER,
    maxWords: 200,
    language: null,
    extraInstruction: null,
    redactOutputLinks: true,
    redactOutputImages: true,
    blockOnOutputLeak: true,
    blockOnExfiltration: true,
    checkGrounding: true,
    checkLexicalGrounding: true,
    tripwire: false,
  };
}

/** Adds data-marking and blocks the model call on CRITICAL pre-scan risk. */
export function strictConfig(): BulwarkConfig {
  return { ...balancedConfig(), spotlightMethods: ["datamark", "delimit"], blockBeforeLlm: "critical", detectionThreshold: 0.4 };
}

/** Base64-encodes content and blocks on HIGH risk. Maximum safety, some quality cost. */
export function paranoidConfig(): BulwarkConfig {
  return { ...balancedConfig(), spotlightMethods: ["base64", "delimit"], blockBeforeLlm: "high", detectionThreshold: 0.3, tripwire: true };
}

export interface PreparedRequest {
  messages: Messages;
  context: PromptContext;
  sanitize: SanitizeResult;
  detect: DetectResult;
  spotlight: SpotlightResult;
  /** The planted positive control, when `BulwarkConfig.tripwire` is on. */
  tripwire?: Tripwire;
}

export class Bulwark {
  readonly config: BulwarkConfig;
  private readonly llm?: LLM;

  constructor(config: Partial<BulwarkConfig> = {}, llm?: LLM) {
    this.config = { ...balancedConfig(), ...config };
    this.llm = llm;
  }

  sanitize(content: string): SanitizeResult {
    let working = content;
    const truncated = working.length > this.config.maxContentChars;
    if (truncated) working = working.slice(0, this.config.maxContentChars);
    const result = sanitize(working, {
      stripHtmlContent: this.config.stripHtml,
      normalizeUnicode: this.config.normalizeUnicode,
      keepEmojiVariation: this.config.keepEmojiVariation,
    });
    if (truncated) {
      result.removed.truncated_chars = 1;
      result.findings.push({
        stage: "sanitize", category: "truncated", severity: "info", weight: 0,
        message: `Input exceeded maxContentChars (${this.config.maxContentChars}) and was truncated`,
      });
    }
    return result;
  }

  /** Folded copy for the detector's second pass — leetspeak and cross-script
   * homoglyph disguises. Detection runs primarily on the un-folded text so
   * legitimate non-Latin scripts and multilingual signatures keep working. */
  private foldedText(san: SanitizeResult): string | undefined {
    return this.config.foldConfusables ? foldDetection(san.text) : undefined;
  }

  /** The raw content, capped. Kept un-sanitized because the decode stage needs
   * the invisible channels that sanitization strips. */
  private truncated(content: string): string {
    return content.slice(0, this.config.maxContentChars);
  }

  private runDetect(content: string, san: SanitizeResult): DetectResult {
    return detect(san.text, {
      threshold: this.config.detectionThreshold,
      extraFindings: san.findings,
      useHeuristics: this.config.useHeuristics,
      alsoScan: this.foldedText(san),
      alsoDecode: this.config.decodeEncoded ? this.truncated(content) : undefined,
      useContext: this.config.useContext,
    });
  }

  /** Sanitize + detect only — no model call. Use to gate content yourself. */
  scan(content: string): DetectResult {
    return this.runDetect(content, this.sanitize(content));
  }

  /** Sanitize, detect, spotlight and build messages — ready for any model. */
  prepare(content: string): PreparedRequest {
    const san = this.sanitize(content);
    const det = this.runDetect(content, san);

    // The tripwire is planted after detection on purpose: it is
    // instruction-shaped, and scanning it would inflate the input's own risk
    // score with Bulwark's own text.
    const wire = this.config.tripwire ? makeTripwire() : undefined;
    const body = wire ? plantTripwire(san.text, wire) : san.text;

    const spot = spotlight(body, { methods: this.config.spotlightMethods, marker: this.config.marker });
    const { messages, context } = buildMessages(spot, {
      maxWords: this.config.maxWords,
      language: this.config.language,
      extraInstruction: this.config.extraInstruction,
    });
    return { messages, context, sanitize: san, detect: det, spotlight: spot, tripwire: wire };
  }

  /** Validate a model reply produced from `prepare`. */
  finalize(rawOutput: string, prepared: PreparedRequest): GuardResult {
    const val = validateOutput(rawOutput, prepared.context, {
      redactLinks: this.config.redactOutputLinks,
      redactImages: this.config.redactOutputImages,
      blockOnLeak: this.config.blockOnOutputLeak,
    });
    return this.assemble(prepared.sanitize, prepared.detect, val, rawOutput, false);
  }

  /** Run the whole pipeline and return a GuardResult. */
  async summarize(content: string, llm?: LLM): Promise<GuardResult> {
    const model = llm ?? this.llm;
    if (!model) {
      throw new Error(
        "No model provided. Pass an llm to summarize(), set new Bulwark({}, llm), or use prepare()/finalize().",
      );
    }
    const prepared = this.prepare(content);
    if (this.config.blockBeforeLlm !== null && severityGte(prepared.detect.risk, this.config.blockBeforeLlm)) {
      return this.assemble(prepared.sanitize, prepared.detect, null, null, true);
    }
    const rawOutput = await model(prepared.messages);
    return this.finalize(rawOutput, prepared);
  }

  private assemble(
    san: SanitizeResult,
    det: DetectResult,
    val: ValidationResult | null,
    rawOutput: string | null,
    blocked: boolean,
  ): GuardResult {
    const findings: Finding[] = val ? [...det.findings, ...val.findings] : [...det.findings];
    const riskScore = scoreFindings(findings);
    const risk = bucket(riskScore);

    // `safe` answers "is the returned summary safe to use?" — not "was the input
    // clean?". A contained injection whose output passed validation is a success.
    const injectionDetected = det.injected;
    let summary: string | null;
    let safe: boolean;
    if (blocked) {
      summary = null;
      safe = false;
    } else {
      summary = val ? val.summary : null;
      safe = !!(val && val.safe);
    }

    const status = blocked ? "BLOCKED" : !safe ? "UNSAFE" : injectionDetected ? "CONTAINED" : "SAFE";
    return {
      safe,
      blocked,
      injectionDetected,
      summary,
      riskScore,
      risk,
      status,
      findings,
      sanitize: san,
      detect: det,
      validation: val,
      rawOutput,
      report: formatReport(status, risk, riskScore, findings),
    };
  }
}
