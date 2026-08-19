"""Nokia SR OS local user passwords ("$2y$" bcrypt hashes).

SR OS stores local user passwords as bcrypt, written in config as
``$2y$10$<22-char salt><31-char digest>``. It is a one-way hash, like Cisco
type 8 and type 9, so `decrypt` always raises; `check` recomputes the hash
from a candidate password using the salt carried in the given value.

The Python `bcrypt` library refuses to generate a "$2y$" salt:
`bcrypt.gensalt(10, prefix=b"2y")` raises ``ValueError: Supported prefixes
are b'2a' or b'2b'``. "2a", "2b" and "2y" are historical tags for the same
underlying algorithm (the tag once marked a Perl/PHP bug in how bcrypt
handled certain high-bit passwords; the fix landed under "2b", and "2y" is
just PHP's spelling of "the fixed algorithm"). They produce byte-identical
digests for the same password and salt: hashing under a "$2b$" salt and
rewriting the prefix to "$2y$" yields exactly what a Nokia device would
carry in its config, and `test_2y_and_2b_produce_an_identical_digest` in
this package's tests pins that equivalence. So this module always computes
under "$2b$" and rewrites the prefix afterwards, rather than trying to coax
the library into emitting "2y" directly.

Public API:
    encrypt(plaintext: str, salt: str | None = None) -> str
    decrypt(ciphertext: str) -> str            # always raises ValueError
    check(ciphertext: str, other: str) -> tuple[str, str, bool]
"""

from __future__ import annotations

import hmac

import bcrypt

__all__ = ["encrypt", "decrypt", "check", "MAGIC", "ACCEPTED_PREFIXES", "DEFAULT_COST"]

MAGIC = "$2y$"
# All three markers are the same bcrypt algorithm; check() accepts any of them.
ACCEPTED_PREFIXES = ("$2a$", "$2b$", "$2y$")
DEFAULT_COST = 10

# bcrypt.gensalt/hashpw only accept these two prefixes; "2y" is handled by
# computing under "2b" and rewriting the prefix (see module docstring).
_LIB_PREFIX = "2b"
_ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
SALT_CHARS = 22
DIGEST_CHARS = 31
_MIN_COST = 4
_MAX_COST = 31


def _split_prefix(text: str) -> tuple[str, str]:
    """Return (prefix_tag, remainder) or raise; prefix_tag is e.g. "2y"."""
    for prefix in ACCEPTED_PREFIXES:
        if text.startswith(prefix):
            return prefix.strip("$"), text[len(prefix):]
    raise ValueError(
        f"Not a Nokia SR OS bcrypt value: must start with one of "
        f"{ACCEPTED_PREFIXES}, got {text!r}"
    )


def _validate_cost(cost: str) -> None:
    if not cost.isdigit():
        raise ValueError(f"bcrypt cost must be numeric: {cost!r}")
    value = int(cost)
    if not (_MIN_COST <= value <= _MAX_COST):
        raise ValueError(
            f"bcrypt cost out of range ({_MIN_COST}-{_MAX_COST}): {value}"
        )


def _validate_chars(rest: str, value: str) -> None:
    for ch in rest:
        if ch not in _ALPHABET:
            raise ValueError(
                f"Character {ch!r} is not in the bcrypt alphabet: {value!r}"
            )


def _parse_fields(value: str) -> tuple[str, str, str]:
    """Parse "$2x$NN$rest" into (prefix_tag, cost, rest); raise ValueError."""
    text = value.strip() if value else ""
    prefix_tag, remainder = _split_prefix(text)
    cost, _sep, rest = remainder.partition("$")
    if not _sep:
        raise ValueError(f"Malformed bcrypt value: {value!r}")
    _validate_cost(cost)
    _validate_chars(rest, value)
    return prefix_tag, cost, rest


def _parse_salt(value: str) -> tuple[str, str, str]:
    """Parse a bare salt "$2x$NN$<22 chars>" into (prefix_tag, cost, salt)."""
    prefix_tag, cost, rest = _parse_fields(value)
    if len(rest) != SALT_CHARS:
        raise ValueError(
            f"Salt must be a {SALT_CHARS}-character bcrypt salt, got "
            f"{len(rest)} characters: {value!r}"
        )
    return prefix_tag, cost, rest


def _parse_hash(value: str) -> tuple[str, str, str, str]:
    """Parse a full hash "$2x$NN$<22 chars><31 chars>" into its four fields."""
    prefix_tag, cost, rest = _parse_fields(value)
    if len(rest) != SALT_CHARS + DIGEST_CHARS:
        raise ValueError(
            f"Malformed bcrypt hash: expected a {SALT_CHARS}-character salt "
            f"followed by a {DIGEST_CHARS}-character digest, got "
            f"{len(rest)} characters after the cost: {value!r}"
        )
    return prefix_tag, cost, rest[:SALT_CHARS], rest[SALT_CHARS:]


def _hashpw(password: str, cost: str, salt: str) -> str:
    """Hash `password` under a "$2b$" salt; return the full result string."""
    lib_salt = f"${_LIB_PREFIX}${cost}${salt}".encode("ascii")
    return bcrypt.hashpw(password.encode("utf-8"), lib_salt).decode("ascii")


def encrypt(plaintext: str, salt: str | None = None) -> str:
    """Hash `plaintext` into a Nokia SR OS "$2y$" bcrypt value.

    Output is non-deterministic: a fresh random salt is drawn on every call,
    so the same password produces a different hash each time. Pass `salt`
    only to reproduce a known value, as the tests do; it is a full bcrypt
    salt string such as "$2y$10$jBwKMP7r.vf4x1tbThl7Y." and carries its own
    cost. The result always carries the "$2y$" prefix, whatever prefix the
    supplied salt used.
    """
    if salt is None:
        cost = f"{DEFAULT_COST:02d}"
        raw_salt = bcrypt.gensalt(DEFAULT_COST, prefix=_LIB_PREFIX.encode("ascii"))
        salt_chars = raw_salt.decode("ascii").split("$")[3]
    else:
        _prefix_tag, cost, salt_chars = _parse_salt(salt)
    full = _hashpw(plaintext, cost, salt_chars)
    return f"{MAGIC}{full[len(f'${_LIB_PREFIX}$'):]}"


def decrypt(ciphertext: str) -> str:
    """Always raises: Nokia SR OS passwords are a one-way hash, not a cipher."""
    raise ValueError(
        "Nokia SR OS passwords are bcrypt hashes and cannot be decrypted. "
        "Use --check to test a password against one."
    )


def check(ciphertext: str, other: str) -> tuple[str, str, bool]:
    """Recompute `ciphertext` from the password `other` and compare.

    The prefix, cost and salt are taken from `ciphertext`, so an equal
    password reproduces the whole string, prefix included: a "$2b$" input
    compares against a "$2b$" recomputation, a "$2y$" input against a
    "$2y$" one. Returns (given, recomputed, match).
    """
    prefix_tag, cost, salt, _digest = _parse_hash(ciphertext)
    full = _hashpw(other, cost, salt)
    given = ciphertext.strip()
    recomputed = f"${prefix_tag}${full[len(f'${_LIB_PREFIX}$'):]}"
    return given, recomputed, hmac.compare_digest(given, recomputed)
