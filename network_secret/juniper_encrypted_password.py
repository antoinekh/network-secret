"""JUNOS local-user "encrypted-password" hashes ("$5$" and "$6$" crypt).

JUNOS stores local user passwords as standard Unix SHA-crypt, written in
config as:

    encrypted-password "$5$itHMToxg$IAeDKDuWsSCoL2W7fognCW8cyNj4YE9ZhDvCoWFC5y/"; ## SECRET-DATA

Two variants are supported, both Ulrich Drepper's SHA-crypt algorithm keyed
by a different hash function (see `_sha_crypt.py` for the shared
implementation):

    $5$  sha256-crypt
    $6$  sha512-crypt

"$1$" (md5crypt) is a distinct, older algorithm and is out of scope: it is
rejected with an error naming it, rather than falling through to a generic
parse failure.

Like Cisco type 8/9 and the Nokia SR OS password format, this is a one-way
hash: `decrypt` always raises, and `check` recomputes the hash from a
candidate password using the salt (and rounds) carried in the given value.

`$5$`/`$6$` embed an optional `rounds=N$` field in the salt, which the
algorithm reads from whatever untrusted value is being checked. Drepper's
spec permits N up to 999,999,999; `openssl passwd` itself will hang for a
very long time computing that. MIN_ROUNDS/MAX_ROUNDS bound what this module
accepts, checked before any hashing happens, following the same precedent as
juniper8.py's PBKDF2 iteration bound and nokia_sros_password.py's bcrypt
cost bound.

Public API:
    encrypt(plaintext: str, salt: str | None = None) -> str
    decrypt(ciphertext: str) -> str            # always raises ValueError
    check(ciphertext: str, other: str) -> tuple[str, str, bool]
"""

from __future__ import annotations

import hmac

from . import _sha_crypt

__all__ = [
    "encrypt",
    "decrypt",
    "check",
    "MAGIC_SHA256",
    "MAGIC_SHA512",
    "DEFAULT_ROUNDS",
    "MIN_ROUNDS",
    "MAX_ROUNDS",
    "SECRET_DATA_MARKER",
]

MAGIC_SHA256 = "$5$"
MAGIC_SHA512 = "$6$"
_MAGIC_MD5 = "$1$"  # explicitly unsupported; named in its own error below

DEFAULT_ROUNDS = 5000
# Drepper's spec allows 1000-999999999. The upper end is read from whatever
# value is being checked, so it must be bounded well below the spec's own
# maximum or a pasted hash can force minutes-to-hours of hashing (see the
# module docstring). 100000 rounds is far above anything JUNOS emits (it
# always uses the 5000 default) while staying near a second worst case -
# measured cost is in the package report.
MIN_ROUNDS = 1000
MAX_ROUNDS = 100_000

SECRET_DATA_MARKER = "## SECRET-DATA"

_ROUNDS_PREFIX = "rounds="
_MAX_SALT_LEN = 16
_HASH_NAME = {MAGIC_SHA256: "sha256", MAGIC_SHA512: "sha512"}
# Encoded-hash length is fixed per variant: 32 bytes -> 43 chars for sha256,
# 64 bytes -> 86 chars for sha512 (see _sha_crypt.encode_digest).
_HASH_FIELD_LEN = {MAGIC_SHA256: 43, MAGIC_SHA512: 86}


def _strip_decoration(value: str) -> str:
    """Strip config decoration a pasted line may carry around the value.

    Repeatedly strips surrounding whitespace, a trailing SECRET_DATA_MARKER,
    a trailing ';', and one layer of matching surrounding quotes, in any
    order and any combination, until none apply. This lets a caller pass the
    whole config line:

        encrypted-password "$5$salt$hash"; ## SECRET-DATA
    """
    text = value
    changed = True
    while changed:
        changed = False
        stripped = text.strip()
        if stripped != text:
            text = stripped
            changed = True
            continue
        if text.endswith(SECRET_DATA_MARKER):
            text = text[: -len(SECRET_DATA_MARKER)]
            changed = True
            continue
        if text.endswith(";"):
            text = text[:-1]
            changed = True
            continue
        if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
            text = text[1:-1]
            changed = True
            continue
    return text


def _parse_prefix(text: str) -> tuple[str, str]:
    """Split a leading "$5$"/"$6$" from `text`; raise ValueError otherwise."""
    if text.startswith(_MAGIC_MD5):
        raise ValueError(
            "$1$ (md5crypt) is not a supported variant: only $5$ "
            "(sha256-crypt) and $6$ (sha512-crypt) are accepted."
        )
    for magic in (MAGIC_SHA256, MAGIC_SHA512):
        if text.startswith(magic):
            return magic, text[len(magic):]
    raise ValueError(
        f"Not a JUNOS encrypted-password value: must start with "
        f"{MAGIC_SHA256!r} or {MAGIC_SHA512!r}, got {text!r}"
    )


def _parse_rounds_number(text: str) -> int:
    if not (text and text.isascii() and text.isdigit()):
        # str.isdigit() is True for non-ASCII digits (e.g. superscript "2")
        # that int() cannot parse; require plain ASCII digits.
        raise ValueError(f"Invalid rounds value: {text!r}")
    value = int(text)
    if not (MIN_ROUNDS <= value <= MAX_ROUNDS):
        raise ValueError(
            f"rounds out of range ({MIN_ROUNDS}-{MAX_ROUNDS}): {value}"
        )
    return value


def _split_rounds(text: str) -> tuple[int, str | None, str]:
    """Split an optional leading "rounds=N$" from `text`.

    Returns (rounds, raw_rounds_field, remainder). `raw_rounds_field` is the
    exact digit substring as given (e.g. "007000"), or None if no "rounds="
    field was present at all. It is kept verbatim, leading zeros and all,
    rather than reduced to `rounds` and reformatted with `str()`: a value
    written by another tool may carry non-canonical digits (openssl accepts
    and computes `rounds=007000` identically to `rounds=7000`), and if
    `_format` re-emitted that field from the int it would silently
    canonicalise it - making `recomputed` diverge from `given` in the rounds
    field alone, and a correct password would then compare as a mismatch.
    The out-of-range check happens here, before any hashing is attempted.
    """
    if text.startswith(_ROUNDS_PREFIX):
        num_part, sep, remainder = text[len(_ROUNDS_PREFIX):].partition("$")
        if not sep:
            raise ValueError(f"Malformed rounds field: {text!r}")
        return _parse_rounds_number(num_part), num_part, remainder
    return DEFAULT_ROUNDS, None, text


def _validate_salt(salt: str) -> None:
    """Reject an empty, over-long, or out-of-alphabet salt.

    Drepper's spec (and openssl) silently truncate a salt longer than
    _MAX_SALT_LEN to that length rather than rejecting it. This module
    rejects instead, deliberately diverging from the spec: it matches this
    codebase's strictness elsewhere (nokia_sros_password rejects a malformed
    salt rather than coercing it), and a real JUNOS device can never emit an
    over-long salt in the first place, since it truncates before writing
    config. Silently accepting input this module would then treat
    differently from the device - by hashing against the untruncated salt -
    is worse than refusing it outright.
    """
    if not salt:
        raise ValueError("Empty salt")
    if len(salt) > _MAX_SALT_LEN:
        raise ValueError(
            f"Salt too long (max {_MAX_SALT_LEN} characters): {salt!r}"
        )
    for ch in salt:
        if ch not in _sha_crypt.ALPHABET:
            raise ValueError(
                f"Character {ch!r} is not in the crypt alphabet: salt {salt!r}"
            )


def _validate_hash_field(hash_field: str, magic: str) -> None:
    if not hash_field:
        raise ValueError("Malformed value: empty hash field")
    for ch in hash_field:
        if ch not in _sha_crypt.ALPHABET:
            raise ValueError(
                f"Character {ch!r} is not in the crypt alphabet: "
                f"hash {hash_field!r}"
            )
    expected = _HASH_FIELD_LEN[magic]
    if len(hash_field) != expected:
        raise ValueError(
            f"Malformed hash field: expected {expected} characters for "
            f"{magic}, got {len(hash_field)}"
        )


def _parse_salt_arg(salt: str) -> tuple[str, int, str | None, str]:
    """Parse an `encrypt()` salt argument into (magic, rounds, rounds_raw, salt).

    Accepts a bare salt ("abcdefgh"), a "rounds=N$salt" form, or either of
    those prefixed with "$5$"/"$6$" to select the variant. With no "$5$"/
    "$6$" prefix, the variant defaults to MAGIC_SHA512. `rounds_raw` is the
    verbatim digit substring (see `_split_rounds`), or None if not given.
    """
    text = salt.strip()
    if text.startswith("$"):
        magic, rest = _parse_prefix(text)
    else:
        magic, rest = MAGIC_SHA512, text
    rounds, rounds_raw, salt_chars = _split_rounds(rest)
    _validate_salt(salt_chars)
    return magic, rounds, rounds_raw, salt_chars


def _parse_value(value: str) -> tuple[str, int, str | None, str, str]:
    """Parse a full "$5$[rounds=N$]salt$hash" value, decoration and all.

    Returns (magic, rounds, rounds_raw, salt, hash_field). `rounds_raw` is
    the verbatim digit substring (see `_split_rounds`), or None if not given.
    """
    text = _strip_decoration(value)
    magic, rest = _parse_prefix(text)
    rounds, rounds_raw, rest = _split_rounds(rest)
    salt, sep, hash_field = rest.partition("$")
    if not sep:
        raise ValueError(f"Malformed value: missing hash field: {value!r}")
    _validate_salt(salt)
    _validate_hash_field(hash_field, magic)
    return magic, rounds, rounds_raw, salt, hash_field


def _compute(magic: str, password: str, salt: str, rounds: int) -> str:
    digest = _sha_crypt.hash_password(password, salt, rounds, _HASH_NAME[magic])
    return _sha_crypt.encode_digest(digest, _HASH_NAME[magic])


def _format(magic: str, rounds_raw: str | None, salt: str, encoded: str) -> str:
    """Assemble "$N$[rounds=<raw>$]salt$hash". See `_split_rounds` for why
    `rounds_raw` is the original digit substring, not `str(rounds)`."""
    rounds_field = f"{_ROUNDS_PREFIX}{rounds_raw}$" if rounds_raw is not None else ""
    return f"{magic}{rounds_field}{salt}${encoded}"


def encrypt(plaintext: str, salt: str | None = None) -> str:
    """Hash `plaintext` into a JUNOS encrypted-password value.

    Emits "$6$" (sha512-crypt) by default, since that is what current JUNOS
    writes. Output is non-deterministic when `salt` is omitted: a fresh
    random 16-character salt is drawn on every call, so the same password
    produces a different hash each time.

    `salt` accepts:
      - a bare salt string, e.g. "abcdefgh" (up to 16 characters from the
        crypt alphabet "./0-9A-Za-z"): hashed at DEFAULT_ROUNDS as "$6$".
      - "rounds=N$abcdefgh": hashed at N rounds (MIN_ROUNDS-MAX_ROUNDS), as
        "$6$", and the output carries the "rounds=N$" field.
      - either of the above prefixed with "$5$" or "$6$" to select the
        variant instead of the "$6$" default, e.g. "$5$abcdefgh" or
        "$5$rounds=10000$abcdefgh".
    """
    if salt is None:
        magic = MAGIC_SHA512
        rounds = DEFAULT_ROUNDS
        rounds_raw = None
        salt_chars = _sha_crypt.generate_salt()
    else:
        magic, rounds, rounds_raw, salt_chars = _parse_salt_arg(salt)
    encoded = _compute(magic, plaintext, salt_chars, rounds)
    return _format(magic, rounds_raw, salt_chars, encoded)


def decrypt(ciphertext: str) -> str:
    """Always raises: encrypted-password is a one-way hash, not a cipher."""
    raise ValueError(
        "JUNOS encrypted-password values are a one-way SHA-crypt hash and "
        "cannot be decrypted. Use --check to test a password against one."
    )


def check(ciphertext: str, other: str) -> tuple[str, str, bool]:
    """Recompute `ciphertext` from the password `other` and compare.

    The variant, rounds, and salt are taken from `ciphertext` (after
    stripping config decoration - see SECRET_DATA_MARKER), so an equal
    password reproduces the whole value - including a non-canonical rounds
    field such as "rounds=007000$", which is preserved verbatim rather than
    reformatted (see `_split_rounds`). Returns (given, recomputed, match).
    """
    magic, rounds, rounds_raw, salt, _hash_field = _parse_value(ciphertext)
    encoded = _compute(magic, other, salt, rounds)
    recomputed = _format(magic, rounds_raw, salt, encoded)
    given = _strip_decoration(ciphertext)
    return given, recomputed, hmac.compare_digest(given, recomputed)
