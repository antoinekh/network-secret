from __future__ import annotations

import pytest

from network_secret import nokia_sros_custom_hash as nokia

# Known-answer vector shared with the web app under web/.
KEY = "a3f8d9e112c04b7af1c3e8b92d057a4e"  # 32 chars -> AES-256
PLAINTEXT = "L@bS3cr3t!"
ENCODED = "Xfs39BMeblOtlorgwTChxQ== custom"


def test_known_answer_decrypt():
    assert nokia.decrypt(ENCODED, KEY) == PLAINTEXT


def test_known_answer_encrypt_is_deterministic():
    # ECB is deterministic: encrypt reproduces the exact vector.
    assert nokia.encrypt(PLAINTEXT, KEY) == ENCODED


def test_round_trip():
    ct = nokia.encrypt("hunter2", KEY)
    assert nokia.decrypt(ct, KEY) == "hunter2"


def test_decrypt_without_suffix():
    assert nokia.decrypt(ENCODED.removesuffix(" custom"), KEY) == PLAINTEXT


@pytest.mark.parametrize(
    "value",
    [
        "Xfs39BMeblOtlorgwTChxQ== custom",  # canonical: one space marker
        "Xfs39BMeblOtlorgwTChxQ== CUSTOM",  # case-insensitive
        "  Xfs39BMeblOtlorgwTChxQ== custom  ",  # surrounding whitespace trimmed
    ],
)
def test_decrypt_suffix_variants(value):
    # SR OS writes "<base64> custom" with exactly one space; matching is
    # case-insensitive and surrounding whitespace is trimmed.
    assert nokia.decrypt(value, KEY) == PLAINTEXT


@pytest.mark.parametrize("klen", [16, 24, 32])
def test_accepts_128_192_256(klen):
    key = "k" * klen
    assert nokia.decrypt(nokia.encrypt("x", key), key) == "x"


@pytest.mark.parametrize("klen", [15, 17, 31, 33])
def test_rejects_bad_key_length(klen):
    with pytest.raises(ValueError):
        nokia.encrypt("x", "k" * klen)


def test_wrong_key_fails():
    ct = nokia.encrypt("hunter2", KEY)
    with pytest.raises(ValueError):
        nokia.decrypt(ct, "b" * 32)


def test_check_match_and_mismatch():
    assert nokia.check(ENCODED, PLAINTEXT, KEY)[2] is True
    assert nokia.check(ENCODED, "nope", KEY)[2] is False
