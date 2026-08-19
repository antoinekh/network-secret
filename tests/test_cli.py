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


def test_list_shows_all_seven(capsys):
    assert main(["--list"]) == 0
    out = capsys.readouterr().out
    for cipher_id in (
        "juniper9",
        "juniper8",
        "nokia-sros-custom-hash",
        "cisco-type6",
        "cisco-type7",
        "cisco-type8",
        "cisco-type9",
    ):
        assert cipher_id in out


def test_type7_round_trip_through_the_cli(capsys):
    assert main(["cisco-type7", "--decrypt", "060506324F41"]) == 0
    assert capsys.readouterr().out.strip() == "cisco"


def test_type6_reads_its_own_env_var(monkeypatch, capsys):
    monkeypatch.setenv("CISCO_MASTER_KEY", "cisco123")
    monkeypatch.delenv("JUNOS_MASTER_PASSWORD", raising=False)
    assert main(["cisco-type6", "--decrypt", "NdUI^_YP[VEPG[MT_bfTEFNZYFCYe\\R\\M"]) == 0
    assert capsys.readouterr().out.strip() == "password"


def test_type6_ignores_the_juniper_env_var(monkeypatch):
    """Regression guard: env vars were once mapped by KeyKind, not by cipher."""
    monkeypatch.delenv("CISCO_MASTER_KEY", raising=False)
    monkeypatch.setenv("JUNOS_MASTER_PASSWORD", "cisco123")
    monkeypatch.setattr(
        "network_secret.cli.getpass.getpass", lambda prompt="": "wrong-key"
    )
    assert main(["cisco-type6", "--decrypt", "NdUI^_YP[VEPG[MT_bfTEFNZYFCYe\\R\\M"]) == 2


def test_type8_check_matches(capsys):
    code = main(
        [
            "cisco-type8",
            "--check",
            "$8$J5J/1K3e8gk974$HRezVpnMZOhOU2uxFTv.79S1U1PpMScizwXS3Z1Dx1s",
            "cisco123",
        ]
    )
    assert code == 0
    assert "YES" in capsys.readouterr().out


def test_type8_check_mismatches():
    code = main(
        [
            "cisco-type8",
            "--check",
            "$8$J5J/1K3e8gk974$HRezVpnMZOhOU2uxFTv.79S1U1PpMScizwXS3Z1Dx1s",
            "wrong",
        ]
    )
    assert code == 1


def test_type9_decrypt_reports_one_way(capsys):
    assert main(["cisco-type9", "--decrypt", "$9$abc$def"]) == 2
    assert "one-way" in capsys.readouterr().err
