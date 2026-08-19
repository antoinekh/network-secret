"""Cisco IOS / IOS-XE type 9 password hashes.

Type 9 is a one-way hash for local users and enable secrets, written in a
config as ``username admin secret 9 $9$salt$hash``. It is scrypt with
N=16384, r=1 and p=1 over the salt's raw ASCII bytes. It replaced type 8 to
raise the memory cost of an offline attack.

Because it is one way, `decrypt` always raises. Use `check` to test a
candidate password against an existing hash.

Note the prefix: a Cisco type 9 hash starts with "$9$", the same marker
Juniper/HPE uses for its own, unrelated substitution cipher. Pick the format
by the device it came from, not by the prefix.

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

MAGIC = "$9$"
TYPE_NUMBER = 9
# scrypt cost parameters IOS uses. N=16384 with r=1 needs about 2 MB.
SCRYPT_N = 16384
SCRYPT_R = 1
SCRYPT_P = 1


def _kdf(password: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=_cisco_hash.DIGEST_LEN,
    )


def encrypt(plaintext: str, salt: str | None = None) -> str:
    """Hash `plaintext` into a Cisco type 9 value.

    Output is non-deterministic: a fresh random salt is drawn on every call,
    so the same password produces a different hash each time. Pass `salt`
    only to reproduce a known value, as the tests do.
    """
    return _cisco_hash.hash_password(plaintext, _kdf, TYPE_NUMBER, salt)


def decrypt(ciphertext: str) -> str:
    """Always raises: type 9 is a one-way hash, not a reversible cipher."""
    raise _cisco_hash.one_way_error(TYPE_NUMBER)


def check(ciphertext: str, other: str) -> tuple[str, str, bool]:
    """Recompute `ciphertext` from the password `other` and compare.

    The salt is taken from `ciphertext`, so an equal password reproduces the
    whole string. Returns (given, recomputed, match).
    """
    return _cisco_hash.verify(ciphertext, other, _kdf, TYPE_NUMBER)
