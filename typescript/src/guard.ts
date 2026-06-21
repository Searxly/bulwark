/**
 * The high-level orchestrator. Wires sanitize → detect → spotlight → harden →
 * validate into one call. Bring any model: `(messages) => string | Promise<string>`.
 */

import { bucket, detect, scoreFindings } from "./detect.js";
import { buildMessages } from "./prompt.js";
import { DEFAULT_MARKER, spotlight } from "./spotlight.js";
import { sanitize } from "./sanitize.js";
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
  // Stage 1 — sanitize
  stripHtml: boolean | "auto";
  normalizeUnicode: boolean;
  keepEmojiVariation: boolean;
  // Stage 2 — detect
  detectionThreshold: number;
  useHeuristics: boolean;
  /** Refuse to call the model when risk reaches this severity (null = never). */
  blockBeforeLlm: Severity | null;
  // Stage 3 — spotlight
  spotlightMethods: string[];
  marker: string;
  // Stage 4 — prompt
  maxWords: number | null;
  language: string | null;
  extraInstruction: string | null;
  // Stage 5 — validate
  redactOutputLinks: boolean;
  redactOutputImages: boolean;
  blockOnOutputLeak: boolean;
}

export function balancedConfig(): BulwarkConfig {
  return {
    stripHtml: "auto",
    normalizeUnicode: true,
    keepEmojiVariation: false,
    detectionThreshold: 0.5,
    useHeuristics: true,
    blockBeforeLlm: null,
    spotlightMethods: ["delimit"],
    marker: DEFAULT_MARKER,
    maxWords: 200,
    language: null,
    extraInstruction: null,
    redactOutputLinks: true,
    redactOutputImages: true,
    blockOnOutputLeak: true,
  };
}

/** Adds data-marking and blocks the model call on CRITICAL pre-scan risk. */
export function strictConfig(): BulwarkConfig {
  return { ...balancedConfig(), spotlightMethods: ["datamark", "delimit"], blockBeforeLlm: "critical", detectionThreshold: 0.4 };
}

/** Base64-encodes content and blocks on HIGH risk. Maximum safety, some quality cost. */
export function paranoidConfig(): BulwarkConfig {
  return { ...balancedConfig(), spotlightMethods: ["base64", "delimit"], blockBeforeLlm: "high", detectionThreshold: 0.3 };
}

export interface PreparedRequest {
  messages: Messages;
  context: PromptContext;
  sanitize: SanitizeResult;
  detect: DetectResult;
  spotlight: SpotlightResult;
}

export class Bulwark {
  readonly config: BulwarkConfig;
  private readonly llm?: LLM;

  constructor(config: Partial<BulwarkConfig> = {}, llm?: LLM) {
    this.config = { ...balancedConfig(), ...config };
    this.llm = llm;
  }

  sanitize(content: string): SanitizeResult {
    return sanitize(content, {
      stripHtmlContent: this.config.stripHtml,
      normalizeUnicode: this.config.normalizeUnicode,
      keepEmojiVariation: this.config.keepEmojiVariation,
    });
  }

  /** Sanitize + detect only — no model call. Use to gate content yourself. */
  scan(content: string): DetectResult {
    const san = this.sanitize(content);
    return detect(san.text, {
      threshold: this.config.detectionThreshold,
      extraFindings: san.findings,
      useHeuristics: this.config.useHeuristics,
    });
  }

  /** Sanitize, detect, spotlight and build messages — ready for any model. */
  prepare(content: string): PreparedRequest {
    const san = this.sanitize(content);
    const det = detect(san.text, {
      threshold: this.config.detectionThreshold,
      extraFindings: san.findings,
      useHeuristics: this.config.useHeuristics,
    });
    const spot = spotlight(san.text, { methods: this.config.spotlightMethods, marker: this.config.marker });
    const { messages, context } = buildMessages(spot, {
      maxWords: this.config.maxWords,
      language: this.config.language,
      extraInstruction: this.config.extraInstruction,
    });
    return { messages, context, sanitize: san, detect: det, spotlight: spot };
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

    let summary: string | null;
    let safe: boolean;
    if (blocked) {
      summary = null;
      safe = false;
    } else if (val) {
      summary = val.summary;
      safe = val.safe && !det.injected;
    } else {
      summary = null;
      safe = !det.injected;
    }

    const status = blocked ? "BLOCKED" : safe ? "SAFE" : "FLAGGED";
    return {
      safe,
      blocked,
      summary,
      riskScore,
      risk,
      findings,
      sanitize: san,
      detect: det,
      validation: val,
      rawOutput,
      report: formatReport(status, risk, riskScore, findings),
    };
  }
}
