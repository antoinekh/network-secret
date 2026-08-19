"""Cisco IOS / IOS-XE type 8 password hashes.

Type 8 is a one-way hash for local users and enable secrets, written in a
config as ``username admin secret 8 $8$salt$hash``. It is PBKDF2-HMAC-SHA256
with 20000 iterations over the salt's raw ASCII bytes.

Because it is one way, `decrypt` always raises. Use `check` to test a
candidate password against an existing hash.

Reference: ios_hash_password.c in
https://github.com/CiscoDevNet/Type-6-Password-Encode

Public API:
    encrypt(plaintext: str, salt: str | None = None) -> str
    decrypt(ciphertext: str) -> str            # always raises ValueError
    check(ciphertext: str, other: str) -> tuple[str, str, bool]
"""

from __future__ import annotations

import hashlib

from . import _cisco_hash

__all__ = ["decrypt", "encrypt", "check"]

MAGIC = "$8$"
ITERATIONS = 20000


def _kdf(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password, salt, ITERATIONS, _cisco_hash.DIGEST_LEN
    )


def encrypt(plaintext: str, salt: str | None = None) -> str:
    """Hash `plaintext` into a Cisco type 8 value.

    Output is non-deterministic: a fresh random salt is drawn on every call,
    so the same password produces a different hash each time. Pass `salt`
    only to reproduce a known value, as the tests do.
    """
    return _cisco_hash.hash_password(plaintext, _kdf, MAGIC, salt)


def decrypt(ciphertext: str) -> str:
    """Always raises: type 8 is a one-way hash, not a reversible cipher."""
    raise _cisco_hash.one_way_error(MAGIC)


def check(ciphertext: str, other: str) -> tuple[str, str, bool]:
    """Recompute `ciphertext` from the password `other` and compare.

    The salt is taken from `ciphertext`, so an equal password reproduces the
    whole string. Returns (given, recomputed, match).
    """
    return _cisco_hash.verify(ciphertext, other, _kdf, MAGIC)
