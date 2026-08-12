"""Pure-logic tests for typosquat candidate generation — no network, no
database. generate_candidates() is split out from the provider specifically
so it's testable this way.
"""

from app.providers.typosquat_provider import generate_candidates


def test_generates_candidates_for_a_normal_domain() -> None:
    pairs = generate_candidates("okta.com")
    assert len(pairs) > 50  # omission/repetition/transposition/keyboard/TLD swap etc.
    domains = [d for d, _ in pairs]
    assert len(domains) == len(set(domains))  # no duplicates


def test_never_returns_the_original_domain() -> None:
    pairs = generate_candidates("okta.com")
    assert all(d != "okta.com" for d, _ in pairs)


def test_tld_swap_produces_expected_candidate() -> None:
    pairs = generate_candidates("okta.com")
    assert ("okta.net", "tld_swap") in pairs
    assert ("okta.io", "tld_swap") in pairs


def test_omission_produces_expected_candidate() -> None:
    pairs = generate_candidates("okta.com")
    domains = {d for d, technique in pairs if technique == "omission"}
    assert "kta.com" in domains  # dropped leading 'o'
    assert "okt.com" in domains  # dropped trailing 'a'


def test_phishing_affixes_produce_expected_candidates() -> None:
    pairs = generate_candidates("okta.com")
    domains = {d for d, _ in pairs}
    assert "secure-okta.com" in domains
    assert "okta-support.com" in domains


def test_homoglyph_substitution() -> None:
    pairs = generate_candidates("okta.com")
    domains = {d for d, technique in pairs if technique == "homoglyph"}
    assert "0kta.com" in domains  # o -> 0


def test_malformed_domain_returns_empty() -> None:
    assert generate_candidates("") == []
    assert generate_candidates("nodots") == []
