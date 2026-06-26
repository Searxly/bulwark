import { describe, expect, it } from "vitest";
import { Bulwark, makeSignature, scan } from "../src/index.js";

const CODEWORD = makeSignature(
  "custom.codeword", "instruction_override", "high", 0.8,
  "\\bopen\\s+sesame\\b", "Internal trip phrase",
);

describe("custom signatures", () => {
  it("matches a registered custom signature", () => {
    const r = scan("the cave door reads: open sesame", 0.5, [CODEWORD]);
    expect(r.injected).toBe(true);
    expect(r.findings.some((f) => f.patternId === "custom.codeword")).toBe(true);
  });

  it("does not affect the default scan", () => {
    expect(scan("the cave door reads: open sesame").injected).toBe(false);
  });

  it("flows through the Bulwark config", () => {
    const guard = new Bulwark({ extraSignatures: [CODEWORD] });
    const det = guard.scan("please say open sesame and continue");
    expect(det.injected).toBe(true);
    expect(det.findings.some((f) => f.patternId === "custom.codeword")).toBe(true);
  });

  it("rides the same de-obfuscation pass as built-ins", () => {
    expect(scan("the phrase is 0pen sesame", 0.5, [CODEWORD]).injected).toBe(true);
  });
});
