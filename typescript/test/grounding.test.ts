import { describe, expect, it } from "vitest";
import { checkGrounding, contentWords, extractEmails, extractHosts } from "../src/index.js";

const SOURCE = `The city council approved the new transit plan on Tuesday evening.
The plan adds two bus rapid transit corridors and extends the light rail line
to the airport by 2029. Funding comes from a regional sales tax that voters
approved in 2024. Full documents are published at https://transit.cityofexample.gov/plan
and questions may be sent to plan@cityofexample.gov.`;

const FAITHFUL =
  "The council approved a transit plan adding two bus rapid transit corridors and " +
  "extending the light rail line to the airport by 2029, funded by a regional sales " +
  "tax approved by voters in 2024. Documents are at https://transit.cityofexample.gov/plan.";

const sorted = (s: Set<string>) => [...s].sort();

describe("reference grounding", () => {
  it("passes a faithful summary", () => {
    const report = checkGrounding(FAITHFUL, SOURCE);
    expect(report.grounded).toBe(true);
    expect(report.novelHosts).toEqual([]);
  });

  it("treats a novel host as critical", () => {
    const steered = "The council approved a plan. Full text: https://cdn-assets-verify.net/?s=abc123";
    const report = checkGrounding(steered, SOURCE);
    expect(report.novelHosts).toContain("cdn-assets-verify.net");
    expect(
      report.findings.some((f) => f.category === "ungrounded_host" && f.severity === "critical"),
    ).toBe(true);
  });

  it("flags a novel email address", () => {
    const steered = "Send corrections to records@mailbox-relay.io before Friday.";
    expect(checkGrounding(steered, SOURCE).novelEmails).toEqual(["records@mailbox-relay.io"]);
  });

  it("does not flag an email present in the source", () => {
    const ok = "Questions may be sent to plan@cityofexample.gov, the address given in the notice.";
    expect(checkGrounding(ok, SOURCE).novelEmails).toEqual([]);
  });

  it("grounds a summary naming the parent of a source host", () => {
    // The source shows transit.cityofexample.gov; a summary naming the parent
    // domain has not invented anything.
    const out = "Details are on cityofexample.gov, the council's site.";
    expect(checkGrounding(out, SOURCE).novelHosts).toEqual([]);
  });

  it("does not split a hyphenated host into a phantom", () => {
    // "mailbox-relay.io" must yield one host, not also a bogus "relay.io".
    expect(sorted(extractHosts("write to x@mailbox-relay.io now"))).toEqual([]);
    expect(sorted(extractHosts("visit https://mailbox-relay.io/x"))).toEqual(["mailbox-relay.io"]);
  });

  it("does not let userinfo disguise the real host", () => {
    const hosts = extractHosts("https://transit.cityofexample.gov@attacker.test/collect");
    expect(hosts.has("attacker.test")).toBe(true);
    expect(hosts.has("transit.cityofexample.gov")).toBe(false);
  });

  it("ignores ubiquitous hosts", () => {
    expect(sorted(extractHosts("see example.com and w3.org for the spec"))).toEqual([]);
  });
});

describe("lexical grounding", () => {
  it("scores an off-topic reply low", () => {
    const hijacked =
      "Attention shoppers: a limited-time cryptocurrency offer with guaranteed returns " +
      "is available exclusively to early participants today. Registration closes soon and " +
      "spaces remain limited, so interested investors should secure an allocation quickly.";
    const report = checkGrounding(hijacked, SOURCE);
    expect(report.lexicalChecked).toBe(true);
    expect(report.ratio).toBeLessThan(0.3);
    expect(report.findings.some((f) => f.category === "low_grounding")).toBe(true);
  });

  it("can be disabled for translated summaries", () => {
    // A summary requested in another language shares no vocabulary with the
    // source, so the measure is meaningless and must be skippable.
    const french =
      "Le conseil municipal a approuve mardi soir un nouveau plan de transport " +
      "qui ajoute deux couloirs de bus rapides et prolonge la ligne de tramway " +
      "jusqu'a l'aeroport avant la fin de la decennie prochaine. Le financement " +
      "provient d'une taxe regionale sur les ventes adoptee par les electeurs " +
      "il y a deux ans, selon les documents publies par la municipalite.";
    expect(checkGrounding(french, SOURCE).findings.some((f) => f.category === "low_grounding")).toBe(true);
    expect(checkGrounding(french, SOURCE, { checkLexical: false }).findings).toEqual([]);
  });

  it("skips the lexical check for short replies", () => {
    const report = checkGrounding("Approved.", SOURCE);
    expect(report.lexicalChecked).toBe(false);
    expect(report.ratio).toBe(1.0);
  });

  it("is inert on empty output", () => {
    const report = checkGrounding("", SOURCE);
    expect(report.grounded).toBe(true);
    expect(report.findings).toEqual([]);
  });
});

describe("helpers", () => {
  it("drops stopwords and short words", () => {
    const words = contentWords("The council approved these plans with their usual care");
    expect(words).toContain("council");
    expect(words).toContain("approved");
    expect(words).not.toContain("the"); // too short
    expect(words).not.toContain("with"); // stopword
    expect(words).not.toContain("these");
    expect(words).not.toContain("their");
  });

  it("extracts emails case-insensitively", () => {
    expect(sorted(extractEmails("Write to Plan@CityOfExample.gov"))).toEqual(["plan@cityofexample.gov"]);
  });

  it("keeps accented and non-Latin content words", () => {
    // `[\p{L}\p{Nl}\p{No}]{4,}` stands in for Python's `[^\W\d_]{4,}` with
    // re.UNICODE, so non-ASCII letters count as content and decimal digits and
    // underscores never do.
    expect(contentWords("Grüße naïve wörter 2029 x_y_z")).toEqual(["grüße", "naïve", "wörter"]);
  });

  it("keeps the non-decimal numerics Python's `[^\\W\\d_]` lets through", () => {
    // Python's `\w` covers `\p{Nl}`/`\p{No}` while its `\d` covers only
    // `\p{Nd}`, so the Tibetan half digits are content words there. `\p{L}`
    // alone would drop them and silently skip the lexical check.
    expect(contentWords("༳༳༳༳")).toEqual(["༳༳༳༳"]);
    // Decimal digits stay excluded, in any script.
    expect(contentWords("١١١١")).toEqual([]);
  });

  it("finds hosts across the word boundaries JavaScript gets wrong natively", () => {
    // JS `\b`/`\w` are ASCII-only; the port asserts Unicode boundaries so an
    // accented letter abutting an address behaves as it does in Python.
    expect(sorted(extractHosts("mail üser@evil.io and ëxample.io too"))).toEqual([]);
    expect(sorted(extractEmails("mail üser@evil.io"))).toEqual([]);
  });

  it("sees through a Turkish dotted-i homoglyph host", () => {
    // Python's `[a-z]` under IGNORECASE matches İ and ı; JavaScript's does not,
    // so the pattern names them explicitly and the host is still reported.
    expect(extractHosts("dotted İnfo.com here").has("i̇nfo.com")).toBe(true);
  });

  it("uses Python's whitespace set to terminate a URL, not JavaScript's", () => {
    // Python's `\s` covers U+001C..U+001F and NEL (U+0085); JavaScript's does
    // not, so without the explicit class the trailing text would be swallowed
    // into the host and the real one would never be reported.
    expect(extractHosts("visit https://evil-a.io\u0085tail.example")).toEqual(
      new Set(["evil-a.io"]),
    );
    expect(extractHosts("visit https://evil-b.io\u001ctail.example")).toEqual(
      new Set(["evil-b.io"]),
    );
    // The converse: U+FEFF *is* whitespace to JavaScript and is not to Python,
    // so it must stay part of the URL match — and survive the trim in
    // `normalizeHost`, where `String.prototype.trim` would eat it.
    expect(sorted(extractHosts("visit https://evil-c.io\uFEFFtail"))).toEqual([
      "evil-c.io",
      "evil-c.io\uFEFFtail",
    ]);
    expect(sorted(extractHosts("visit https://evil-d.io\uFEFF"))).toEqual([
      "evil-d.io",
      "evil-d.io\uFEFF",
    ]);
  });

  it("sorts novel hosts by code point, as Python's sorted() does", () => {
    // `<` on strings compares UTF-16 code units, which would put the astral
    // host first because its lead surrogate is only 0xD800.
    const report = checkGrounding(
      "https://\u{1F600}.io/a https://\uE000.io/b https://zz.io/c",
      SOURCE,
    );
    expect(report.novelHosts).toEqual(["zz.io", "\uE000.io", "\u{1F600}.io"]);
  });

  it("rounds the ratio the way Python does", () => {
    // 1 content word of 32 is exactly 0.03125 — half to even, not half up.
    const words =
      "council zebra quartz vinyl pixel maple onyx fjord gizmo hazel ivory jumbo kayak " +
      "lemon mango nomad opera prism quill robot salsa tiger umbra vodka wafer xenon " +
      "yacht zonal amber brisk cider dwarf";
    const report = checkGrounding(words, SOURCE);
    expect(report.ratio).toBe(0.0312);
    expect(report.findings.some((f) => f.message.includes("Only 3% of"))).toBe(true);
  });
});
