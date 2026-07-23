"""pytest suite for network_secret.juniper8."""

from __future__ import annotations

import pytest

from network_secret import juniper8

MASTER = "master-secret"

# Master password and $8$ values captured from a real JUNOS 23.2 device.
# Source: juniper8-crypt upstream test suite.
DEVICE_MASTER = "a3f8d9e112c04b7af1c3e8b92d057a4e"

KNOWN_VECTORS = [
    (
        "$8$aes256-gcm$hmac-sha2-256$100$p8XEvHtxRNE$d/hqRmh5etkBzo7WSdtvjg$"
        "7w1eMTYXkz4RdzMF9CAkJQ$qVLunbFwBWwyxln2Vg",
        "LabBgpSecret1",
    ),
    (
        "$8$aes256-gcm$hmac-sha2-256$100$32kBriS21/k$0O08cy0znzu4nrcHxbhMmA$"
        "PP0OeY9ANX2UDT1FTDVpiQ$gTrzX/ZppBbu42TpRtw",
        "LabIsisSecret1",
    ),
]


@pytest.mark.parametrize("ciphertext,expected", KNOWN_VECTORS)
def test_decrypt_device_known_vectors(ciphertext: str, expected: str) -> None:
    """Device-verified known-answer test: proves cross-version parity."""
    assert juniper8.decrypt(ciphertext, DEVICE_MASTER) == expected


def test_round_trip():
    ct = juniper8.encrypt("hunter2", MASTER)
    assert juniper8.decrypt(ct, MASTER) == "hunter2"


def test_non_deterministic():
    assert juniper8.encrypt("x", MASTER) != juniper8.encrypt("x", MASTER)


def test_wrong_master_fails():
    ct = juniper8.encrypt("hunter2", MASTER)
    with pytest.raises(ValueError):
        juniper8.decrypt(ct, "wrong-master")


def test_check_match_and_mismatch():
    ct = juniper8.encrypt("hunter2", MASTER)
    assert juniper8.check(ct, "hunter2", MASTER)[2] is True
    assert juniper8.check(ct, "nope", MASTER)[2] is False


def test_check_other_is_ciphertext():
    a = juniper8.encrypt("same", MASTER)
    b = juniper8.encrypt("same", MASTER)
    assert juniper8.check(a, b, MASTER)[2] is True


def test_decrypt_rejects_non_magic():
    with pytest.raises(ValueError):
        juniper8.decrypt("$9$nope", MASTER)


def test_decrypt_rejects_non_ascii_iteration_count():
    # str.isdigit() is True for non-ASCII digits (e.g. superscript "²") that
    # int() cannot parse; the dedicated message must still be raised.
    value = KNOWN_VECTORS[0][0].replace("$100$", "$²$", 1)
    with pytest.raises(ValueError, match="Invalid iteration count"):
        juniper8.decrypt(value, DEVICE_MASTER)
