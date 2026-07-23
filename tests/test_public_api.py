from __future__ import annotations

import network_secret


def test_modules_exposed():
    assert network_secret.juniper8.decrypt(
        network_secret.juniper8.encrypt("x", "M"), "M"
    ) == "x"
    assert network_secret.juniper9.decrypt(
        network_secret.juniper9.encrypt("x")
    ) == "x"
    key = "a3f8d9e112c04b7af1c3e8b92d057a4e"
    assert network_secret.nokia_sros_custom_hash.decrypt(
        network_secret.nokia_sros_custom_hash.encrypt("x", key), key
    ) == "x"


def test_version_is_string():
    assert isinstance(network_secret.__version__, str)
