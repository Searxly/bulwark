/** Tripwire: a positive control that proves whether the model obeyed content. */

import { describe, expect, it } from "vitest";
import { check, makeTripwire, plant, redact } from "../src/tripwire.js";
import type { Tripwire } from "../src/tripwire.js";

const ZWSP = String.fromCodePoint(0x200b);

/** A wire with a chosen token, for pinning behaviour that randomness would hide. */
const wireFor = (token: string): Tripwire => ({
  token,
  sentence: `Document integrity check: ... ${token} ...`,
  squashed: token.replace(/[^A-Za-z0-9]+/g, "").toUpperCase(),
});

describe("tripwire", () => {
  it("mints a unique token per request", () => {
    const tokens = new Set(Array.from({ length: 50 }, () => makeTripwire().token));
    expect(tokens.size, "a reused token is one an attacker can pre-emptively echo").toBe(50);
  });

  it("carries the token in the sentence", () => {
    const wire = makeTripwire();
    expect(wire.sentence.includes(wire.token)).toBe(true);
  });

  it("appends the tripwire after the content", () => {
    const wire = makeTripwire();
    const planted = plant("The council approved the transit plan.", wire);
    expect(planted.startsWith("The council approved the transit plan.")).toBe(true);
    expect(planted.endsWith(wire.sentence)).toBe(true);
  });

  it("handles empty content", () => {
    const wire = makeTripwire();
    expect(plant("", wire)).toBe(wire.sentence);
  });

  // --- firing -------------------------------------------------------------

  it("reports echoing the token as a critical finding", () => {
    const wire = makeTripwire();
    const findings = check(`The council approved the plan. ${wire.token}`, wire);
    expect(findings.length).toBe(1);
    expect(findings[0]!.category).toBe("tripwire_tripped");
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.stage).toBe("validate");
  });

  it("is not tripped by a clean summary", () => {
    const wire = makeTripwire();
    expect(check("The council approved the transit plan on Tuesday evening.", wire)).toEqual([]);
  });

  it("ignores case", () => {
    const wire = makeTripwire();
    expect(check(wire.token.toLowerCase(), wire).length).toBe(1);
  });

  it("still counts a spaced-out echo", () => {
    // Splitting the code to dodge a filter is still obeying the content.
    const wire = makeTripwire();
    expect(check([...wire.token].join(" "), wire).length).toBe(1);
  });

  it("still counts an echo split by invisibles", () => {
    const wire = makeTripwire();
    expect(check([...wire.token].join(ZWSP), wire).length).toBe(1);
  });

  it("still counts markdown emphasis inside the token", () => {
    const wire = makeTripwire();
    const head = wire.token.slice(0, 4);
    const tail = wire.token.slice(4);
    expect(check(`${head}**${tail}**`, wire).length).toBe(1);
  });

  it("returns nothing without a wire or without output", () => {
    expect(check("anything at all", null)).toEqual([]);
    expect(check("anything at all", undefined)).toEqual([]);
    expect(check("", makeTripwire())).toEqual([]);
  });

  // --- redaction ----------------------------------------------------------

  it("removes the token when redacting", () => {
    const wire = makeTripwire();
    const cleaned = redact(`Summary text. ${wire.token} More text.`, wire);
    expect(cleaned.includes(wire.token)).toBe(false);
    expect(cleaned.includes("[redacted]")).toBe(true);
    expect(cleaned.includes("Summary text.")).toBe(true);
    expect(cleaned.includes("More text.")).toBe(true);
  });

  it("redacts case-insensitively and every occurrence", () => {
    const wire = makeTripwire();
    const cleaned = redact(`${wire.token.toLowerCase()} and ${wire.token}`, wire);
    expect(cleaned).toBe("[redacted] and [redacted]");
  });

  it("is a no-op without a wire", () => {
    expect(redact("untouched", null)).toBe("untouched");
  });

  it("leaves a reply that never echoed the token alone", () => {
    const wire = wireFor("QUARTZ-7F3A9C");
    const text = "The council approved the transit plan. QUARTZ-7F3A9D was not it.";
    expect(redact(text, wire)).toBe(text);
  });

  // Python's `re.IGNORECASE` folds with the simple lowercase mapping plus an
  // equivalence table; JavaScript's `i` flag folds far less. These pin the
  // wider net, because a token echoed in exotic casing has still leaked.
  it("redacts a token wearing exotic casing", () => {
    expect(redact("BAſALT-01F2E3 is the code", wireFor("BASALT-01F2E3")))
      .toBe("[redacted] is the code");
    // U+212A KELVIN SIGN standing in for K.
    expect(redact("KRAKEN-0K0K0K", wireFor("KRAKEN-0K0K0K"))).toBe("[redacted]");
    expect(redact("MERIDıAN-ABCDEF", wireFor("MERIDIAN-ABCDEF"))).toBe("[redacted]");
    // U+0130 lowercases to a bare "i" under the simple mapping.
    expect(redact("MERİDIAN-ABCDEF", wireFor("MERIDIAN-ABCDEF"))).toBe("[redacted]");
    expect(redact("ςIGMA-000001", wireFor("σIGMA-000001"))).toBe("[redacted]");
    expect(redact("μICRO-000002", wireFor("µICRO-000002"))).toBe("[redacted]");
  });

  it("folds by code point, so an astral token survives redaction intact", () => {
    const wire = wireFor("\u{1f600}-ABCDEF");
    expect(redact("code \u{1f600}-abcdef here", wire)).toBe("code [redacted] here");
  });

  it("replaces non-overlapping matches, leftmost first", () => {
    expect(redact("AAAAA", wireFor("AAA"))).toBe("[redacted]AA");
  });

  // --- shape of the minted token ------------------------------------------

  it("mints a word-shaped token with six hex digits", () => {
    for (let i = 0; i < 20; i++) {
      expect(makeTripwire().token).toMatch(
        /^(QUARTZ|BASALT|CINDER|HARBOR|LANTERN|MERIDIAN|OBSIDIAN|PELICAN|SAFFRON|TUNDRA|VERMILION|ZEPHYR)-[0-9A-F]{6}$/,
      );
    }
  });

  it("exposes the token with separators removed", () => {
    const wire = makeTripwire();
    expect(wire.squashed).toBe(wire.token.replace("-", ""));
  });
});
