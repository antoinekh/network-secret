"""Cisco type 7 known-answer vectors, round trips, and rejection cases."""

from __future__ import annotations

import pytest

from network_secret import cisco_type7


def test_decrypt_known_vector():
    assert cisco_type7.decrypt("060506324F41") == "cisco"


def test_encrypt_known_vector_with_fixed_seed():
    assert cisco_type7.encrypt("cisco", seed=6) == "060506324F41"


def test_encrypt_uses_a_seed_ios_would_emit():
    for _ in range(50):
        seed = int(cisco_type7.encrypt("secret")[:2])
        assert 0 <= seed <= cisco_type7.MAX_ENCRYPT_SEED


def test_round_trip_every_seed():
    for seed in range(len(cisco_type7.KEY)):
        assert cisco_type7.decrypt(cisco_type7.encrypt("L@bS3cr3t!", seed=seed)) == "L@bS3cr3t!"


def test_round_trip_empty_string():
    assert cisco_type7.decrypt(cisco_type7.encrypt("", seed=0)) == ""


def test_check_treats_other_as_cleartext():
    assert cisco_type7.check("060506324F41", "cisco") == ("cisco", "cisco", True)
    assert cisco_type7.check("060506324F41", "nope") == ("cisco", "nope", False)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0",
        "AB1234",        # seed is not decimal
        "060506324F4",   # odd number of hex digits
        "06ZZ",          # not hex
        "530506324F41",  # seed beyond the key length
    ],
)
def test_decrypt_rejects_malformed(value):
    with pytest.raises(ValueError):
        cisco_type7.decrypt(value)


def test_encrypt_rejects_out_of_range_seed():
    with pytest.raises(ValueError):
        cisco_type7.encrypt("cisco", seed=53)


def test_encrypt_rejects_non_latin1():
    with pytest.raises(ValueError):
        cisco_type7.encrypt("secret€")
