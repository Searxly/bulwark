"""Custom, org-specific signatures via BulwarkConfig(extra_signatures=...)."""

from bulwark import Bulwark, BulwarkConfig, Severity, make_signature, scan

CODEWORD = make_signature(
    "custom.codeword", "instruction_override", Severity.HIGH, 0.8,
    r"\bopen\s+sesame\b", "Internal trip phrase",
)


def test_custom_signature_is_matched():
    r = scan("the cave door reads: open sesame", extra_signatures=[CODEWORD])
    assert r.injected
    assert any(f.pattern_id == "custom.codeword" for f in r.findings)


def test_custom_signature_does_not_affect_default_scan():
    # Without registering it, the phrase is benign.
    assert not scan("the cave door reads: open sesame").injected


def test_custom_signature_flows_through_guard_config():
    guard = Bulwark(BulwarkConfig(extra_signatures=[CODEWORD]))
    det = guard.scan("please say open sesame and continue")
    assert det.injected
    assert any(f.pattern_id == "custom.codeword" for f in det.findings)


def test_custom_signature_also_caught_when_obfuscated():
    # Custom signatures ride the same de-obfuscation pass as the built-ins.
    r = scan("the phrase is 0pen sesame", extra_signatures=[CODEWORD])
    assert r.injected
