"""Cisco type 8 known-answer vectors, verification, and rejection cases."""

from __future__ import annotations

import pytest

from network_secret import cisco_type8

VECTOR_PASSWORD = "cisco123"
VECTOR_SALT = "J5J/1K3e8gk974"
VECTOR_HASH = "$8$J5J/1K3e8gk974$HRezVpnMZOhOU2uxFTv.79S1U1PpMScizwXS3Z1Dx1s"


def test_encrypt_known_vector():
    assert cisco_type8.encrypt(VECTOR_PASSWORD, salt=VECTOR_SALT) == VECTOR_HASH


def test_encrypt_generates_a_fresh_salt_each_call():
    first = cisco_type8.encrypt(VECTOR_PASSWORD)
    second = cisco_type8.encrypt(VECTOR_PASSWORD)
    assert first != second
    assert first.startswith("$8$")


def test_generated_salt_is_fourteen_alphabet_characters():
    salt = cisco_type8.encrypt("x").split("$")[2]
    assert len(salt) == 14
    assert all(c in cisco_type8._cisco_hash.ALPHABET for c in salt)


def test_check_accepts_the_right_password():
    given, recomputed, match = cisco_type8.check(VECTOR_HASH, VECTOR_PASSWORD)
    assert given == VECTOR_HASH
    assert recomputed == VECTOR_HASH
    assert match is True


def test_check_rejects_the_wrong_password():
    given, recomputed, match = cisco_type8.check(VECTOR_HASH, "wrong")
    assert given == VECTOR_HASH
    assert recomputed != VECTOR_HASH
    assert match is False


def test_check_round_trips_a_generated_hash():
    value = cisco_type8.encrypt("L@bS3cr3t!")
    assert cisco_type8.check(value, "L@bS3cr3t!")[2] is True


def test_decrypt_always_raises_and_says_one_way():
    with pytest.raises(ValueError, match="one-way"):
        cisco_type8.decrypt(VECTOR_HASH)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-hash",
        "$9$ihSswXDbk0kaVK$o.uyR2nMrWtjMkrQwBXUR5lVuVt/KzG23rmYvshODXI",  # type 9
        "$8$J5J/1K3e8gk974",                 # missing the hash field
        "$8$J5J/1K3e8gk974$",                # empty hash field
        "$8$J5J/1K3e8gk974$abc$def",         # too many fields
        "$8$J5J/1K3e8gk974$abc+def",         # '+' is not in the Cisco alphabet
        "$8$has space$abcdef",               # space is not a legal salt character
    ],
)
def test_check_rejects_malformed(value):
    with pytest.raises(ValueError):
        cisco_type8.check(value, "cisco123")


@pytest.mark.parametrize(
    "bad_salt,reason",
    [
        ("", "empty salt"),
        ("salt$with$dollar", "contains $"),
        ("salt with space", "contains space"),
        ("café", "contains non-ASCII"),
        ("salt\x00null", "contains non-printable"),
        ("salt\x1fcontrol", "contains non-printable control character"),
    ],
)
def test_encrypt_rejects_invalid_salt(bad_salt, reason):
    """validate_salt rejects five conditions: empty, $, space, non-ASCII, non-printable."""
    with pytest.raises(ValueError):
        cisco_type8.encrypt("password", salt=bad_salt)


def test_encrypt_accepts_valid_non_fourteen_character_salt():
    """validate_salt deliberately does not check length; IOS devices may carry other lengths."""
    short_salt = "abc"
    long_salt = "abcdefghijklmnopqrstuvwxyz"
    short_hash = cisco_type8.encrypt("password", salt=short_salt)
    long_hash = cisco_type8.encrypt("password", salt=long_salt)
    assert short_hash.startswith("$8$abc$")
    assert long_hash.startswith(f"$8${long_salt}$")
