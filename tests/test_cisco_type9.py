"""Cisco type 9 known-answer vectors, verification, and rejection cases."""

from __future__ import annotations

import pytest

from network_secret import cisco_type9

VECTOR_PASSWORD = "cisco123"
VECTOR_SALT = "ihSswXDbk0kaVK"
VECTOR_HASH = "$9$ihSswXDbk0kaVK$o.uyR2nMrWtjMkrQwBXUR5lVuVt/KzG23rmYvshODXI"


def test_encrypt_known_vector():
    assert cisco_type9.encrypt(VECTOR_PASSWORD, salt=VECTOR_SALT) == VECTOR_HASH


def test_scrypt_parameters_match_ios():
    assert (cisco_type9.SCRYPT_N, cisco_type9.SCRYPT_R, cisco_type9.SCRYPT_P) == (
        16384,
        1,
        1,
    )


def test_encrypt_generates_a_fresh_salt_each_call():
    first = cisco_type9.encrypt(VECTOR_PASSWORD)
    second = cisco_type9.encrypt(VECTOR_PASSWORD)
    assert first != second
    assert first.startswith("$9$")


def test_check_accepts_the_right_password():
    assert cisco_type9.check(VECTOR_HASH, VECTOR_PASSWORD)[2] is True


def test_check_rejects_the_wrong_password():
    assert cisco_type9.check(VECTOR_HASH, "wrong")[2] is False


def test_check_round_trips_a_generated_hash():
    value = cisco_type9.encrypt("L@bS3cr3t!")
    assert cisco_type9.check(value, "L@bS3cr3t!")[2] is True


def test_decrypt_always_raises_and_says_one_way():
    with pytest.raises(ValueError, match="one-way"):
        cisco_type9.decrypt(VECTOR_HASH)


def test_a_type_8_hash_is_not_a_type_9_hash():
    with pytest.raises(ValueError):
        cisco_type9.check(
            "$8$J5J/1K3e8gk974$HRezVpnMZOhOU2uxFTv.79S1U1PpMScizwXS3Z1Dx1s",
            "cisco123",
        )
