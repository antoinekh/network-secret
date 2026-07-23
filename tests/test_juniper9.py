"""pytest suite for network_secret.juniper9."""

from __future__ import annotations

import pytest

from network_secret import juniper9


def test_known_answer_decrypt():
    # Real vector from juniper9-crypt test suite: "$9$FNkC3/t1IcevLuOWx" decrypts to "hello".
    assert juniper9.decrypt("$9$FNkC3/t1IcevLuOWx") == "hello"


def test_round_trip():
    assert juniper9.decrypt(juniper9.encrypt("S3cr3t!")) == "S3cr3t!"


def test_check_match_and_mismatch():
    ct = juniper9.encrypt("hunter2")
    assert juniper9.check(ct, "hunter2")[2] is True
    assert juniper9.check(ct, "nope")[2] is False


def test_check_other_is_ciphertext():
    a = juniper9.encrypt("same")
    b = juniper9.encrypt("same")
    assert juniper9.check(a, b)[2] is True


def test_decrypt_rejects_non_magic():
    with pytest.raises(ValueError):
        juniper9.decrypt("not-a-9-string")
