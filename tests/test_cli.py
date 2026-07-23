from __future__ import annotations

import pytest

from network_secret.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "network-secret" in capsys.readouterr().out


def test_list(capsys):
    assert main(["--list"]) == 0
    out = capsys.readouterr().out
    assert "juniper9" in out
    assert "juniper8" in out
    assert "nokia-sros-custom-hash" in out


def test_juniper9_round_trip(capsys):
    assert main(["juniper9", "--encrypt", "hunter2"]) == 0
    ct = capsys.readouterr().out.strip()
    assert main(["juniper9", "--decrypt", ct]) == 0
    assert capsys.readouterr().out.strip() == "hunter2"


def test_juniper8_encrypt_decrypt(capsys):
    assert main(["juniper8", "-m", "MASTER", "--encrypt", "hunter2"]) == 0
    ct = capsys.readouterr().out.strip()
    assert main(["juniper8", "-m", "MASTER", "--decrypt", ct]) == 0
    assert capsys.readouterr().out.strip() == "hunter2"


def test_nokia_round_trip(capsys):
    key = "a3f8d9e112c04b7af1c3e8b92d057a4e"
    assert main(["nokia-sros-custom-hash", "-k", key, "--encrypt", "hunter2"]) == 0
    ct = capsys.readouterr().out.strip()
    assert main(["nokia-sros-custom-hash", "-k", key, "--decrypt", ct]) == 0
    assert capsys.readouterr().out.strip() == "hunter2"


def test_check_match_returns_0(capsys):
    main(["juniper9", "--encrypt", "hunter2"])
    ct = capsys.readouterr().out.strip()
    assert main(["juniper9", "--check", ct, "hunter2"]) == 0


def test_check_mismatch_returns_1(capsys):
    main(["juniper9", "--encrypt", "hunter2"])
    ct = capsys.readouterr().out.strip()
    assert main(["juniper9", "--check", ct, "nope"]) == 1


def test_error_returns_2():
    assert main(["juniper8", "-m", "MASTER", "--decrypt", "not-a-real-8"]) == 2


def test_nokia_key_from_env(monkeypatch, capsys):
    monkeypatch.setenv("SROS_CUSTOM_HASH_KEY", "a3f8d9e112c04b7af1c3e8b92d057a4e")
    assert main(["nokia-sros-custom-hash", "--encrypt", "hunter2"]) == 0
    # The Nokia format appends " custom" as a marker, so a successful encrypt
    # with the env-var key produces a value ending in "custom".
    assert capsys.readouterr().out.strip().endswith("custom")


def test_juniper8_master_from_env(monkeypatch, capsys):
    monkeypatch.setenv("JUNOS_MASTER_PASSWORD", "MASTER")
    assert main(["juniper8", "--encrypt", "hunter2"]) == 0
    ct = capsys.readouterr().out.strip()
    assert main(["juniper8", "--decrypt", ct]) == 0
    assert capsys.readouterr().out.strip() == "hunter2"


def test_check_output_format(capsys):
    main(["juniper9", "--encrypt", "hunter2"])
    ct = capsys.readouterr().out.strip()
    main(["juniper9", "--check", ct, "hunter2"])
    out = capsys.readouterr().out
    assert "Value 1   : 'hunter2'" in out
    assert "Value 2   : 'hunter2'" in out
    assert "Match     : YES" in out
