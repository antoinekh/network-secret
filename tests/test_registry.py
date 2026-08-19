from __future__ import annotations

from network_secret.registry import REGISTRY, find
from network_secret.types import KeyKind


def test_registry_ids_and_order():
    assert [c.id for c in REGISTRY] == [
        "juniper9",
        "juniper8",
        "nokia-sros-custom-hash",
        "nokia-sros-password",
        "cisco-type6",
        "cisco-type7",
        "cisco-type8",
        "cisco-type9",
    ]


def test_find_returns_cipher_or_none():
    assert find("juniper8").vendor == "Juniper/HPE"
    assert find("does-not-exist") is None


def test_key_kinds():
    assert find("juniper9").key_kind is KeyKind.NONE
    assert find("juniper8").key_kind is KeyKind.MASTER_PASSWORD
    assert find("nokia-sros-custom-hash").key_kind is KeyKind.SHARED_KEY


def test_operations_wired():
    j9 = find("juniper9")
    assert j9.decrypt(j9.encrypt("hunter2")) == "hunter2"


import pytest

CISCO_IDS = ["cisco-type6", "cisco-type7", "cisco-type8", "cisco-type9"]


@pytest.mark.parametrize("cipher_id", CISCO_IDS)
def test_cisco_ciphers_are_registered(cipher_id):
    assert find(cipher_id) is not None


def test_registry_holds_eight_ciphers():
    assert len(REGISTRY) == 8


def test_registry_ids_are_unique():
    ids = [c.id for c in REGISTRY]
    assert len(ids) == len(set(ids))


def test_keyed_ciphers_declare_an_env_var():
    for cipher in REGISTRY:
        if cipher.keyed:
            assert cipher.env_var, f"{cipher.id} is keyed but declares no env_var"


def test_env_vars_are_unique():
    env_vars = [c.env_var for c in REGISTRY if c.env_var]
    assert len(env_vars) == len(set(env_vars))


def test_cisco_type6_uses_its_own_env_var():
    assert find("cisco-type6").env_var == "CISCO_MASTER_KEY"
    assert find("juniper8").env_var == "JUNOS_MASTER_PASSWORD"


def test_one_way_ciphers_say_so_in_their_name():
    for cipher_id in ("cisco-type8", "cisco-type9"):
        assert "one-way" in find(cipher_id).name


def test_one_way_ciphers_have_no_key():
    for cipher_id in ("cisco-type8", "cisco-type9"):
        assert find(cipher_id).key_kind is KeyKind.NONE
