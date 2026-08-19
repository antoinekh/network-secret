"""Cisco type 6 known-answer vectors, round trips, and rejection cases."""

from __future__ import annotations

import pytest

from network_secret import cisco_type6

# Cisco's own vector, from test_vector_generate_type_6 in test_vector.c.
VECTOR_MASTER = "cisco123"
VECTOR_PLAIN = "password"
VECTOR_SALT = bytes.fromhex("5b0c394ba0198a98")  # base41 "NdUI^_YP[VEP"
VECTOR_VALUE = "NdUI^_YP[VEPG[MT_bfTEFNZYFCYe\\R\\M"

# A value taken from a real router, published in encode6.py.
DEVICE_MASTER = "Cisco123"
DEVICE_VALUE = "fe_a`iJYE\\DZYJhDhTP[`MYaTgRH_MAAB"
DEVICE_PLAIN = "Cisco123"


def test_encrypt_reproduces_the_cisco_vector_exactly():
    """Regression guard for the trailing NUL byte.

    IOS encrypts and authenticates len+1 bytes. Drop the NUL and this
    vector's tail becomes '^MUbJYAAB' instead of 'YFCYe\\R\\M'.
    """
    assert (
        cisco_type6.encrypt(VECTOR_PLAIN, VECTOR_MASTER, salt=VECTOR_SALT)
        == VECTOR_VALUE
    )


def test_decrypt_the_cisco_vector():
    assert cisco_type6.decrypt(VECTOR_VALUE, VECTOR_MASTER) == VECTOR_PLAIN


def test_decrypt_a_real_device_value():
    assert cisco_type6.decrypt(DEVICE_VALUE, DEVICE_MASTER) == DEVICE_PLAIN


def test_encrypt_is_non_deterministic():
    first = cisco_type6.encrypt(VECTOR_PLAIN, VECTOR_MASTER)
    second = cisco_type6.encrypt(VECTOR_PLAIN, VECTOR_MASTER)
    assert first != second
    assert cisco_type6.decrypt(first, VECTOR_MASTER) == VECTOR_PLAIN
    assert cisco_type6.decrypt(second, VECTOR_MASTER) == VECTOR_PLAIN


@pytest.mark.parametrize(
    "plaintext",
    ["", "a", "L@bS3cr3t!", "x" * 15, "x" * 16, "x" * 17, "x" * 200, "clé-secrète"],
)
def test_round_trip(plaintext):
    value = cisco_type6.encrypt(plaintext, "MyMaster")
    assert cisco_type6.decrypt(value, "MyMaster") == plaintext


def test_decrypt_rejects_the_wrong_master_key():
    with pytest.raises(ValueError, match="Authentication failed"):
        cisco_type6.decrypt(VECTOR_VALUE, "not-the-master-key")


def test_check_treats_other_as_cleartext():
    assert cisco_type6.check(VECTOR_VALUE, "password", VECTOR_MASTER) == (
        "password",
        "password",
        True,
    )
    assert cisco_type6.check(VECTOR_VALUE, "nope", VECTOR_MASTER)[2] is False


@pytest.mark.parametrize(
    "value",
    [
        "",
        "AAAA",       # length is not a multiple of 3
        "AAA",        # decodes to fewer than 13 bytes
        "AA!",        # '!' is not in the base41 alphabet
        "iii" * 7,    # a group above 65535
    ],
)
def test_decrypt_rejects_malformed(value):
    with pytest.raises(ValueError):
        cisco_type6.decrypt(value, VECTOR_MASTER)


def test_encrypt_rejects_a_bad_salt_length():
    with pytest.raises(ValueError, match="Salt must be"):
        cisco_type6.encrypt("x", VECTOR_MASTER, salt=b"short")


def test_encrypt_accepts_the_longest_valid_plaintext():
    # MAX_PLAINTEXT_LEN plus the NUL is exactly 256 blocks, the most the
    # one-byte counter can address.
    value = cisco_type6.encrypt("x" * cisco_type6.MAX_PLAINTEXT_LEN, VECTOR_MASTER)
    assert cisco_type6.decrypt(value, VECTOR_MASTER) == "x" * cisco_type6.MAX_PLAINTEXT_LEN


def test_encrypt_rejects_an_oversized_plaintext():
    with pytest.raises(ValueError, match="too long"):
        cisco_type6.encrypt("x" * (cisco_type6.MAX_PLAINTEXT_LEN + 1), VECTOR_MASTER)
