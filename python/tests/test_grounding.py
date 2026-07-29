"""Output grounding: is the reply actually derived from the source?"""

from bulwark.grounding import check_grounding, content_words, extract_emails, extract_hosts

SOURCE = """The city council approved the new transit plan on Tuesday evening.
The plan adds two bus rapid transit corridors and extends the light rail line
to the airport by 2029. Funding comes from a regional sales tax that voters
approved in 2024. Full documents are published at https://transit.cityofexample.gov/plan
and questions may be sent to plan@cityofexample.gov."""

FAITHFUL = (
    "The council approved a transit plan adding two bus rapid transit corridors and "
    "extending the light rail line to the airport by 2029, funded by a regional sales "
    "tax approved by voters in 2024. Documents are at https://transit.cityofexample.gov/plan."
)


# --- reference grounding ---------------------------------------------------

def test_faithful_summary_is_grounded():
    report = check_grounding(FAITHFUL, SOURCE)
    assert report.grounded
    assert not report.novel_hosts


def test_novel_host_is_critical():
    steered = "The council approved a plan. Full text: https://cdn-assets-verify.net/?s=abc123"
    report = check_grounding(steered, SOURCE)
    assert "cdn-assets-verify.net" in report.novel_hosts
    assert any(f.category == "ungrounded_host" and f.severity.value == "critical"
               for f in report.findings)


def test_novel_email_is_flagged():
    steered = "Send corrections to records@mailbox-relay.io before Friday."
    report = check_grounding(steered, SOURCE)
    assert report.novel_emails == ["records@mailbox-relay.io"]


def test_email_present_in_source_is_not_flagged():
    ok = "Questions may be sent to plan@cityofexample.gov, the address given in the notice."
    assert check_grounding(ok, SOURCE).novel_emails == []


def test_subdomain_of_a_source_host_is_grounded():
    # The source shows transit.cityofexample.gov; a summary naming the parent
    # domain has not invented anything.
    out = "Details are on cityofexample.gov, the council's site."
    assert check_grounding(out, SOURCE).novel_hosts == []


def test_hyphenated_host_is_not_split_into_a_phantom():
    # "mailbox-relay.io" must yield one host, not also a bogus "relay.io".
    assert extract_hosts("write to x@mailbox-relay.io now") == set()
    assert extract_hosts("visit https://mailbox-relay.io/x") == {"mailbox-relay.io"}


def test_userinfo_does_not_disguise_the_real_host():
    hosts = extract_hosts("https://transit.cityofexample.gov@attacker.test/collect")
    assert "attacker.test" in hosts
    assert "transit.cityofexample.gov" not in hosts


def test_ubiquitous_hosts_are_ignored():
    assert extract_hosts("see example.com and w3.org for the spec") == set()


# --- lexical grounding -----------------------------------------------------

def test_off_topic_reply_scores_low_grounding():
    hijacked = (
        "Attention shoppers: a limited-time cryptocurrency offer with guaranteed returns "
        "is available exclusively to early participants today. Registration closes soon and "
        "spaces remain limited, so interested investors should secure an allocation quickly."
    )
    report = check_grounding(hijacked, SOURCE)
    assert report.lexical_checked
    assert report.ratio < 0.30
    assert any(f.category == "low_grounding" for f in report.findings)


def test_lexical_check_can_be_disabled_for_translated_summaries():
    # A summary requested in another language shares no vocabulary with the
    # source, so the measure is meaningless and must be skippable.
    french = ("Le conseil municipal a approuve mardi soir un nouveau plan de transport "
              "qui ajoute deux couloirs de bus rapides et prolonge la ligne de tramway "
              "jusqu'a l'aeroport avant la fin de la decennie prochaine. Le financement "
              "provient d'une taxe regionale sur les ventes adoptee par les electeurs "
              "il y a deux ans, selon les documents publies par la municipalite.")
    assert any(f.category == "low_grounding" for f in check_grounding(french, SOURCE).findings)
    assert check_grounding(french, SOURCE, check_lexical=False).findings == []


def test_short_replies_skip_the_lexical_check():
    report = check_grounding("Approved.", SOURCE)
    assert not report.lexical_checked
    assert report.ratio == 1.0


def test_empty_output_is_inert():
    report = check_grounding("", SOURCE)
    assert report.grounded
    assert report.findings == []


# --- helpers ---------------------------------------------------------------

def test_content_words_drops_stopwords_and_short_words():
    words = content_words("The council approved these plans with their usual care")
    assert "council" in words and "approved" in words
    assert "the" not in words and "with" not in words   # stopword / too short
    assert "these" not in words and "their" not in words


def test_extract_emails_is_case_insensitive():
    assert extract_emails("Write to Plan@CityOfExample.gov") == {"plan@cityofexample.gov"}
