"""Tripwire: a positive control that proves whether the model obeyed content."""

from bulwark.tripwire import check, make_tripwire, plant, redact


def test_tokens_are_unique_per_request():
    tokens = {make_tripwire().token for _ in range(50)}
    assert len(tokens) == 50, "a reused token is one an attacker can pre-emptively echo"


def test_sentence_carries_the_token():
    wire = make_tripwire()
    assert wire.token in wire.sentence


def test_plant_appends_after_the_content():
    wire = make_tripwire()
    planted = plant("The council approved the transit plan.", wire)
    assert planted.startswith("The council approved the transit plan.")
    assert planted.endswith(wire.sentence)


def test_plant_handles_empty_content():
    wire = make_tripwire()
    assert plant("", wire) == wire.sentence


# --- firing ---------------------------------------------------------------

def test_echoing_the_token_is_a_critical_finding():
    wire = make_tripwire()
    findings = check(f"The council approved the plan. {wire.token}", wire)
    assert len(findings) == 1
    assert findings[0].category == "tripwire_tripped"
    assert findings[0].severity.value == "critical"


def test_a_clean_summary_does_not_trip_it():
    wire = make_tripwire()
    assert check("The council approved the transit plan on Tuesday evening.", wire) == []


def test_case_is_ignored():
    wire = make_tripwire()
    assert check(wire.token.lower(), wire)


def test_a_spaced_out_echo_still_counts():
    # Splitting the code to dodge a filter is still obeying the content.
    wire = make_tripwire()
    assert check(" ".join(wire.token), wire)


def test_an_echo_split_by_invisibles_still_counts():
    wire = make_tripwire()
    smuggled = "​".join(wire.token)
    assert check(smuggled, wire)


def test_markdown_emphasis_inside_the_token_still_counts():
    wire = make_tripwire()
    head, tail = wire.token[:4], wire.token[4:]
    assert check(f"{head}**{tail}**", wire)


def test_no_wire_means_no_findings():
    assert check("anything at all", None) == []
    assert check("", make_tripwire()) == []


# --- redaction ------------------------------------------------------------

def test_redaction_removes_the_token():
    wire = make_tripwire()
    cleaned = redact(f"Summary text. {wire.token} More text.", wire)
    assert wire.token not in cleaned
    assert "[redacted]" in cleaned
    assert "Summary text." in cleaned and "More text." in cleaned


def test_redaction_is_a_no_op_without_a_wire():
    assert redact("untouched", None) == "untouched"
