"""pytest suite for network_secret.juniper_encrypted_password."""

from __future__ import annotations

import shutil
import subprocess
import time

import pytest

from network_secret import juniper_encrypted_password as jep

_HAVE_OPENSSL = shutil.which("openssl") is not None


def _openssl_passwd(variant: str, salt: str, password: str) -> str:
    result = subprocess.run(
        ["openssl", "passwd", f"-{variant}", "-salt", salt, password],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


VECTOR_PASSWORD = "lab123"
# Real value from a device.
VECTOR_SHA256 = "$5$itHMToxg$IAeDKDuWsSCoL2W7fognCW8cyNj4YE9ZhDvCoWFC5y/"
# Generated with `openssl passwd -6 -salt OV3tvDvc lab123`.
VECTOR_SHA512 = (
    "$6$OV3tvDvc$QT3FzP8LWnxLDCfDLKibn1.EzGS5crupCiea7Kbi2W4Y9Z1kYu9EYTxs/"
    "z344U8Mwh4QtwlnbUiLZWUHyhrZl1"
)


# --- Known-answer vectors -----------------------------------------------


def test_check_accepts_the_sha256_vector():
    given, recomputed, match = jep.check(VECTOR_SHA256, VECTOR_PASSWORD)
    assert given == VECTOR_SHA256
    assert recomputed == VECTOR_SHA256
    assert match is True


def test_check_accepts_the_sha512_vector():
    given, recomputed, match = jep.check(VECTOR_SHA512, VECTOR_PASSWORD)
    assert given == VECTOR_SHA512
    assert recomputed == VECTOR_SHA512
    assert match is True


def test_encrypt_reproduces_the_sha256_vector():
    assert jep.encrypt(VECTOR_PASSWORD, salt="$5$itHMToxg") == VECTOR_SHA256


def test_encrypt_reproduces_the_sha512_vector():
    assert jep.encrypt(VECTOR_PASSWORD, salt="$6$OV3tvDvc") == VECTOR_SHA512


def test_check_rejects_the_wrong_password():
    given, recomputed, match = jep.check(VECTOR_SHA256, "wrong")
    assert given == VECTOR_SHA256
    assert recomputed != VECTOR_SHA256
    assert match is False


# --- Round trips and defaults --------------------------------------------


def test_encrypt_defaults_to_sha512():
    value = jep.encrypt(VECTOR_PASSWORD)
    assert value.startswith(jep.MAGIC_SHA512)


def test_encrypt_generates_a_fresh_salt_each_call():
    first = jep.encrypt(VECTOR_PASSWORD)
    second = jep.encrypt(VECTOR_PASSWORD)
    assert first != second


@pytest.mark.parametrize("magic", [jep.MAGIC_SHA256, jep.MAGIC_SHA512])
def test_round_trip_both_variants(magic):
    value = jep.encrypt("L@bS3cr3t!", salt=f"{magic}abcdefgh")
    assert value.startswith(magic)
    assert jep.check(value, "L@bS3cr3t!")[2] is True
    assert jep.check(value, "wrong")[2] is False


def test_bare_salt_selects_default_variant_and_rounds():
    value = jep.encrypt(VECTOR_PASSWORD, salt="abcdefgh")
    assert value.startswith(jep.MAGIC_SHA512)
    assert "rounds=" not in value
    assert jep.check(value, VECTOR_PASSWORD)[2] is True


# --- rounds= form ----------------------------------------------------


def test_rounds_form_is_honoured_and_round_trips():
    value = jep.encrypt(VECTOR_PASSWORD, salt="$6$rounds=10000$abcdefgh")
    assert value.startswith("$6$rounds=10000$abcdefgh$")
    assert jep.check(value, VECTOR_PASSWORD)[2] is True
    assert jep.check(value, "wrong")[2] is False


def test_rounds_form_cross_checked_against_openssl_default_variant():
    """salt="rounds=N$salt" with no $5$/$6$ prefix defaults to $6$."""
    value = jep.encrypt(VECTOR_PASSWORD, salt="rounds=7000$abcdefgh")
    assert value.startswith("$6$rounds=7000$abcdefgh$")


def test_check_preserves_the_rounds_field_of_the_given_value():
    """A value with an explicit, already-canonical rounds= field, even at
    the default count, must round-trip with that field intact (glibc/
    openssl do the same). Non-canonical rounds fields are covered separately
    below, against oracle-derived vectors rather than our own encrypt()."""
    value = jep.encrypt(VECTOR_PASSWORD, salt="$5$rounds=5000$abcdefgh")
    assert value.startswith("$5$rounds=5000$abcdefgh$")
    given, recomputed, match = jep.check(value, VECTOR_PASSWORD)
    assert given == value
    assert recomputed == value
    assert match is True


@pytest.mark.parametrize("magic", [jep.MAGIC_SHA256, jep.MAGIC_SHA512])
def test_encrypt_canonicalises_a_non_canonical_rounds_field(magic):
    """encrypt() mints a *new* value, so it must never inherit a
    non-canonical rounds= field (e.g. leading zeros) from the salt argument:
    "rounds=007000" in must produce "rounds=7000" out. This is the opposite
    rule from check(), which preserves what it is given (see the
    non-canonical-rounds tests below) - encrypt() always normalises,
    matching `openssl passwd`'s own output convention.
    """
    value = jep.encrypt(VECTOR_PASSWORD, salt=f"{magic}rounds=007000$abcdefgh")
    assert value.startswith(f"{magic}rounds=7000$abcdefgh$")
    assert "rounds=007000$" not in value


@pytest.mark.skipif(not _HAVE_OPENSSL, reason="openssl is not available")
def test_encrypt_canonical_rounds_output_matches_openssl_sha256():
    variant = "5"
    expected = _openssl_passwd(variant, "rounds=007000$abcdefgh", VECTOR_PASSWORD)
    value = jep.encrypt(VECTOR_PASSWORD, salt="$5$rounds=007000$abcdefgh")
    assert value == expected


@pytest.mark.skipif(not _HAVE_OPENSSL, reason="openssl is not available")
def test_encrypt_canonical_rounds_output_matches_openssl_sha512():
    variant = "6"
    expected = _openssl_passwd(variant, "rounds=007000$abcdefgh", VECTOR_PASSWORD)
    value = jep.encrypt(VECTOR_PASSWORD, salt="$6$rounds=007000$abcdefgh")
    assert value == expected


# The hash fields below are the digests from `openssl passwd -5/-6 -salt
# 'rounds=007000$abcdefgh' lab123`: openssl accepts the leading zeros as
# input but normalises its own output to "rounds=7000$", so these vectors
# are built by hand-splicing a non-canonical "rounds=007000$" prefix onto
# openssl's real digest - never by calling this package's own encrypt() -
# so the test cannot be satisfied by two bugs agreeing with each other.
_NON_CANONICAL_ROUNDS_VECTOR_SHA256 = (
    "$5$rounds=007000$abcdefgh$kdN5PnJqWO7Kjpjd.tXEYwKq64Z2SoXjgo2SqSFCC87"
)
_NON_CANONICAL_ROUNDS_VECTOR_SHA512 = (
    "$6$rounds=007000$abcdefgh$sI/ipHpgRHdKDg6kPyRGMV6JVrTreVzWJzNDcNGlIi."
    "FrxqaOd5hmrrFI20S/gEmON6Tj46C4X/NpaPpRPpkx0"
)


@pytest.mark.parametrize(
    "vector",
    [_NON_CANONICAL_ROUNDS_VECTOR_SHA256, _NON_CANONICAL_ROUNDS_VECTOR_SHA512],
)
def test_check_accepts_a_correct_password_against_non_canonical_rounds(vector):
    """Regression: a correct password must not report as a mismatch just
    because the given value's rounds= field has non-canonical leading
    zeros."""
    given, recomputed, match = jep.check(vector, "lab123")
    assert given == vector
    assert "rounds=007000$" in given
    assert recomputed == vector
    assert match is True


@pytest.mark.parametrize(
    "vector",
    [_NON_CANONICAL_ROUNDS_VECTOR_SHA256, _NON_CANONICAL_ROUNDS_VECTOR_SHA512],
)
def test_check_rejects_a_wrong_password_against_non_canonical_rounds(vector):
    given, recomputed, match = jep.check(vector, "wrong")
    assert given == vector
    assert recomputed != vector
    assert match is False


def test_no_rounds_field_when_not_specified():
    value = jep.encrypt(VECTOR_PASSWORD, salt="$5$abcdefgh")
    assert "rounds=" not in value


# --- Marker and quote stripping ------------------------------------------


def test_marker_is_stripped():
    value = f"{VECTOR_SHA256} {jep.SECRET_DATA_MARKER}"
    assert jep.check(value, VECTOR_PASSWORD)[2] is True


def test_quotes_are_stripped():
    value = f'"{VECTOR_SHA256}"'
    assert jep.check(value, VECTOR_PASSWORD)[2] is True


def test_single_quotes_are_stripped():
    value = f"'{VECTOR_SHA256}'"
    assert jep.check(value, VECTOR_PASSWORD)[2] is True


def test_semicolon_is_stripped():
    value = f"{VECTOR_SHA256};"
    assert jep.check(value, VECTOR_PASSWORD)[2] is True


def test_full_pasted_config_line_is_accepted():
    # As pasted from `show configuration system login user ... | display set`,
    # minus the leading keyword: quotes, semicolon and marker all present.
    value = f'"{VECTOR_SHA256}"; {jep.SECRET_DATA_MARKER}'
    given, recomputed, match = jep.check(value, VECTOR_PASSWORD)
    assert given == VECTOR_SHA256
    assert recomputed == VECTOR_SHA256
    assert match is True


def test_check_given_is_the_stripped_value():
    value = f'"{VECTOR_SHA256}"; {jep.SECRET_DATA_MARKER}'
    given, _recomputed, _match = jep.check(value, VECTOR_PASSWORD)
    assert given == VECTOR_SHA256


def test_whitespace_around_value_is_stripped():
    value = f"   {VECTOR_SHA256}   "
    assert jep.check(value, VECTOR_PASSWORD)[2] is True


# --- $1$ (md5crypt) explicitly out of scope -------------------------------


def test_md5crypt_is_rejected_by_name():
    with pytest.raises(ValueError, match=r"\$1\$"):
        jep.check("$1$abcdefgh$somehash", VECTOR_PASSWORD)


def test_md5crypt_salt_argument_is_rejected_by_name():
    with pytest.raises(ValueError, match=r"\$1\$"):
        jep.encrypt(VECTOR_PASSWORD, salt="$1$abcdefgh")


# --- decrypt always raises -------------------------------------------------


def test_decrypt_always_raises():
    with pytest.raises(ValueError, match="one-way"):
        jep.decrypt(VECTOR_SHA256)


def test_decrypt_raises_even_for_garbage():
    with pytest.raises(ValueError):
        jep.decrypt("not a real value at all")


# --- Out-of-range and malformed rounds -------------------------------------


def test_rounds_below_minimum_is_rejected():
    value = f"$5$rounds={jep.MIN_ROUNDS - 1}$abcdefgh$" + "a" * 43
    with pytest.raises(ValueError, match=f"{jep.MIN_ROUNDS}-{jep.MAX_ROUNDS}"):
        jep.check(value, VECTOR_PASSWORD)


def test_rounds_above_maximum_is_rejected():
    value = f"$5$rounds={jep.MAX_ROUNDS + 1}$abcdefgh$" + "a" * 43
    with pytest.raises(ValueError, match=f"{jep.MIN_ROUNDS}-{jep.MAX_ROUNDS}"):
        jep.check(value, VECTOR_PASSWORD)


def test_huge_rounds_value_is_rejected_quickly():
    """The critical guard: rounds=999999999 is within Drepper's own spec
    range, and even `openssl passwd` hangs computing it (confirmed by hand:
    it did not return within two minutes). If a refactor ever moved the
    bounds check after the hashing, this test would hang instead of failing
    fast, so the timing assertion is the point of the test, not just
    pytest.raises.
    """
    value = "$6$rounds=999999999$abcdefgh$" + "a" * 86
    started = time.perf_counter()
    with pytest.raises(ValueError, match=f"{jep.MIN_ROUNDS}-{jep.MAX_ROUNDS}"):
        jep.check(value, VECTOR_PASSWORD)
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0


def test_malformed_rounds_non_numeric():
    value = "$5$rounds=abc$abcdefgh$" + "a" * 43
    with pytest.raises(ValueError, match="Invalid rounds value"):
        jep.check(value, VECTOR_PASSWORD)


def test_malformed_rounds_empty():
    value = "$5$rounds=$abcdefgh$" + "a" * 43
    with pytest.raises(ValueError, match="Invalid rounds value"):
        jep.check(value, VECTOR_PASSWORD)


def test_malformed_rounds_missing_separator():
    value = "$5$rounds=5000"  # no '$' after the rounds number at all
    with pytest.raises(ValueError, match="Malformed rounds field"):
        jep.check(value, VECTOR_PASSWORD)


def test_encrypt_rejects_out_of_range_rounds_in_salt_argument():
    with pytest.raises(ValueError, match=f"{jep.MIN_ROUNDS}-{jep.MAX_ROUNDS}"):
        jep.encrypt(VECTOR_PASSWORD, salt="rounds=999999999$abcdefgh")


# --- Malformed salt ----------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "$5$$" + "a" * 43,  # empty salt field
        "$5$" + "a" * 17 + "$" + "a" * 43,  # salt too long (17 chars)
        "$5$abc def$" + "a" * 43,  # space is not in the crypt alphabet
        "$5$ab+cd$" + "a" * 43,  # '+' is not in the crypt alphabet
    ],
)
def test_check_rejects_malformed_salt(value):
    with pytest.raises(ValueError):
        jep.check(value, VECTOR_PASSWORD)


@pytest.mark.parametrize(
    "bad_salt",
    [
        "",
        "a" * 17,  # too long
        "abc def",  # space not in alphabet
        "$1$abcdefgh",  # unsupported variant
    ],
)
def test_encrypt_rejects_malformed_salt_argument(bad_salt):
    with pytest.raises(ValueError):
        jep.encrypt(VECTOR_PASSWORD, salt=bad_salt)


def test_salt_at_exactly_the_max_length_is_accepted():
    """Boundary: a 16-character salt is the longest a real device ever
    writes, and must not be rejected by the length check (which compares
    with '>', not '>=')."""
    salt_16 = "a" * 16
    value = jep.encrypt(VECTOR_PASSWORD, salt=f"$5${salt_16}")
    assert value.startswith(f"$5${salt_16}$")
    assert jep.check(value, VECTOR_PASSWORD)[2] is True


# --- Empty / malformed values --------------------------------------------


def test_check_rejects_empty_value():
    with pytest.raises(ValueError):
        jep.check("", VECTOR_PASSWORD)


def test_check_rejects_value_with_no_recognised_prefix():
    with pytest.raises(ValueError, match=r"\$5\$.*\$6\$"):
        jep.check("not-a-crypt-value", VECTOR_PASSWORD)


def test_check_rejects_value_missing_hash_field():
    with pytest.raises(ValueError, match="Malformed value"):
        jep.check("$5$abcdefgh", VECTOR_PASSWORD)


def test_check_rejects_wrong_length_hash_field():
    with pytest.raises(ValueError, match="Malformed hash field"):
        jep.check("$5$abcdefgh$tooshort", VECTOR_PASSWORD)


def test_check_rejects_hash_field_with_invalid_characters():
    value = "$5$abcdefgh$" + ("!" * 43)
    with pytest.raises(ValueError):
        jep.check(value, VECTOR_PASSWORD)


# --- Cross-check against openssl (independent implementation) -------------


@pytest.mark.skipif(not _HAVE_OPENSSL, reason="openssl is not available")
@pytest.mark.parametrize(
    "variant,salt,password",
    [
        ("5", "itHMToxg", "lab123"),
        ("6", "OV3tvDvc", "lab123"),
        ("5", "abcdefgh", "hunter2"),
        ("6", "abcdefgh", "hunter2"),
        ("5", "Z9x2Qw1a", "a very long passphrase with spaces!"),
        ("6", "Z9x2Qw1a", "a very long passphrase with spaces!"),
        ("6", "12345678", "P@ssw0rd"),
    ],
)
def test_matches_openssl_passwd(variant, salt, password):
    expected = _openssl_passwd(variant, salt, password)
    magic = jep.MAGIC_SHA256 if variant == "5" else jep.MAGIC_SHA512
    mine = jep.encrypt(password, salt=f"{magic}{salt}")
    assert mine == expected


@pytest.mark.skipif(not _HAVE_OPENSSL, reason="openssl is not available")
def test_matches_openssl_passwd_with_custom_rounds():
    expected = _openssl_passwd("6", "rounds=10000$abcdefgh", "lab123")
    mine = jep.encrypt("lab123", salt="$6$rounds=10000$abcdefgh")
    assert mine == expected
