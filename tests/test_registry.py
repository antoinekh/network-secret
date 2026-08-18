from __future__ import annotations

from network_secret.registry import REGISTRY, find
from network_secret.types import KeyKind


def test_registry_ids_and_order():
    assert [c.id for c in REGISTRY] == [
        "juniper9",
        "juniper8",
        "nokia-sros-custom-hash",
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
