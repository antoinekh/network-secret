"""Nokia SR OS $2y$ (bcrypt) known-answer vectors, verification, and rejection cases."""

from __future__ import annotations

import bcrypt
import pytest

from network_secret import nokia_sros_password as nokia

VECTOR_PASSWORD = "lab123"
VECTOR_SALT = "$2y$10$jBwKMP7r.vf4x1tbThl7Y."
VECTOR_HASH = "$2y$10$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe"


def test_encrypt_known_vector():
    assert nokia.encrypt(VECTOR_PASSWORD, salt=VECTOR_SALT) == VECTOR_HASH


def test_check_accepts_the_right_password():
    given, recomputed, match = nokia.check(VECTOR_HASH, VECTOR_PASSWORD)
    assert given == VECTOR_HASH
    assert recomputed == VECTOR_HASH
    assert match is True


def test_check_rejects_the_wrong_password():
    given, recomputed, match = nokia.check(VECTOR_HASH, "wrong")
    assert given == VECTOR_HASH
    assert recomputed != VECTOR_HASH
    assert match is False


@pytest.mark.parametrize("prefix", ["$2a$", "$2b$", "$2y$"])
def test_check_accepts_all_three_prefixes_and_preserves_the_given_one(prefix):
    value = prefix + VECTOR_HASH[len(nokia.MAGIC):]
    given, recomputed, match = nokia.check(value, VECTOR_PASSWORD)
    assert given == value
    assert match is True
    assert recomputed.startswith(prefix)


def test_encrypt_generates_a_fresh_salt_each_call():
    first = nokia.encrypt(VECTOR_PASSWORD)
    second = nokia.encrypt(VECTOR_PASSWORD)
    assert first != second
    assert first.startswith(nokia.MAGIC)


def test_encrypt_output_verifies():
    value = nokia.encrypt("L@bS3cr3t!")
    assert nokia.check(value, "L@bS3cr3t!")[2] is True


def test_2y_and_2b_produce_an_identical_digest():
    """Pinned deliberately: $2y$ and $2b$ are the same algorithm with a
    different historical tag. If the bcrypt library's handling of these
    markers ever changes, this test is the one that should fail and explain
    why nokia_sros_password.py rewrites the prefix instead of asking the
    library for $2y$ directly.
    """
    b2_salt = "$2b$10$jBwKMP7r.vf4x1tbThl7Y."
    computed = bcrypt.hashpw(VECTOR_PASSWORD.encode("utf-8"), b2_salt.encode("ascii"))
    assert computed.decode("ascii") == "$2b$" + VECTOR_HASH[len(nokia.MAGIC):]


def test_bcrypt_library_cannot_generate_2y_salts():
    """Pinned deliberately, per the same reasoning as the test above."""
    with pytest.raises(ValueError, match="Supported prefixes"):
        bcrypt.gensalt(10, prefix=b"2y")


def test_decrypt_always_raises_and_says_hash():
    with pytest.raises(ValueError, match="bcrypt hash"):
        nokia.decrypt(VECTOR_HASH)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-hash",
        "lab123",
        "$8$J5J/1K3e8gk974$HRezVpnMZOhOU2uxFTv.79S1U1PpMScizwXS3Z1Dx1s",  # Cisco type 8
        VECTOR_SALT,  # truncated: salt only, no digest field
        "$2y$10$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUo",  # truncated digest
        "$2y$xx$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe",  # non-numeric cost
        "$2y$99$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe",  # out-of-range cost
        "$2y$10$jBwKMP7r.vf4x1tbThl7Y+.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe",  # '+' not in the alphabet
        "$2z$10$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe",  # unrecognised prefix
    ],
)
def test_check_rejects_malformed(value):
    with pytest.raises(ValueError):
        nokia.check(value, VECTOR_PASSWORD)


@pytest.mark.parametrize(
    "bad_salt",
    [
        "",
        "not-a-salt",
        "$2y$10$",  # empty salt field
        "$2y$10$tooshort",  # salt too short
        "$2y$xx$jBwKMP7r.vf4x1tbThl7Y.",  # non-numeric cost
        "$2y$99$jBwKMP7r.vf4x1tbThl7Y.",  # out-of-range cost
        "$2y$10$jBwKMP7r.vf4x1tbThl7+.",  # '+' not in the bcrypt alphabet
        "$2z$10$jBwKMP7r.vf4x1tbThl7Y.",  # unrecognised prefix
    ],
)
def test_encrypt_rejects_invalid_salt(bad_salt):
    with pytest.raises(ValueError):
        nokia.encrypt(VECTOR_PASSWORD, salt=bad_salt)
