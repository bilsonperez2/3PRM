import pytest
from pydantic import ValidationError

from app.schemas.vendor import VendorCreate, validate_domain


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("EXAMPLE.com", "example.com"),
        ("https://example.com/path?x=1", "example.com"),
        ("http://sub.example.com", "sub.example.com"),
        ("www.example.co.uk", "www.example.co.uk"),
    ],
)
def test_validate_domain_normalizes(raw: str, expected: str) -> None:
    assert validate_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not a domain",
        "localhost",  # no TLD
        "example.com; rm -rf /",
        "exa mple.com",
        "-example.com",
        "a" * 300 + ".com",
    ],
)
def test_validate_domain_rejects_invalid_input(raw: str) -> None:
    with pytest.raises(ValueError):
        validate_domain(raw)


def test_vendor_create_rejects_shell_metacharacters_in_domain() -> None:
    with pytest.raises(ValidationError):
        VendorCreate(name="Acme", primary_domain="acme.com`whoami`")
