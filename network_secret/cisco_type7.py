"""Cisco IOS / IOS-XE type 7 passwords.

Type 7 is Cisco's legacy reversible obfuscation, written in a config as
``password 7 060506324F41``. It is not encryption: the key is a fixed string
present in every IOS image, so anyone can recover any type 7 value. It
survives because existing configurations are full of it, and reading those
configurations is the reason this module exists.

The encoded form is a two-digit decimal seed followed by uppercase hex pairs.
Byte ``i`` of the plaintext is XORed with ``KEY[(seed + i) % len(KEY)]``.

IOS emits a seed of 0 to 15 and limits a type 7 password to 25 characters, so
the index never passes 40 and the modulo never wraps in practice. The modulo
is defensive only.

Public API:
    encrypt(plaintext: str, seed: int | None = None) -> str
    decrypt(ciphertext: str) -> str
    check(ciphertext: str, other: str) -> tuple[str, str, bool]
"""

from __future__ import annotations

import random

__all__ = ["decrypt", "encrypt", "check"]

KEY = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"
# IOS only ever emits a seed in this range, so encrypt() stays inside it.
# decrypt() accepts any seed the key length can index.
MAX_ENCRYPT_SEED = 15


def _xor(data: bytes, seed: int) -> bytes:
    return bytes(b ^ ord(KEY[(seed + i) % len(KEY)]) for i, b in enumerate(data))


def encrypt(plaintext: str, seed: int | None = None) -> str:
    """Encode plaintext as a Cisco type 7 value.

    Output is non-deterministic: the seed is chosen at random unless one is
    given, so the same plaintext yields a different string each call. All of
    them decode to the same plaintext. `random` (not `secrets`) is used
    deliberately, since type 7 has no cryptographic strength at all: a
    stronger RNG buys nothing.
    """
    if seed is None:
        seed = random.randint(0, MAX_ENCRYPT_SEED)
    if not 0 <= seed < len(KEY):
        raise ValueError(f"Seed must be between 0 and {len(KEY) - 1}; got {seed}")
    try:
        data = plaintext.encode("latin-1")
    except UnicodeEncodeError as e:
        raise ValueError(
            "Only single-byte (Latin-1) characters can be type 7 encoded"
        ) from e
    body = "".join(f"{b:02X}" for b in _xor(data, seed))
    return f"{seed:02d}{body}"


def decrypt(ciphertext: str) -> str:
    """Decode a Cisco type 7 value back to plaintext."""
    text = ciphertext.strip()
    if len(text) < 2:
        raise ValueError("Not a Cisco type 7 value: too short to hold a seed")
    seed_text = text[:2]
    if not (seed_text.isascii() and seed_text.isdigit()):
        raise ValueError(
            f"Invalid type 7 seed {seed_text!r}: expected two decimal digits"
        )
    seed = int(seed_text)
    if seed >= len(KEY):
        raise ValueError(f"Type 7 seed {seed} out of range (0-{len(KEY) - 1})")
    body = text[2:]
    if len(body) % 2:
        raise ValueError("Malformed type 7 value: the hex body has an odd length")
    try:
        raw = bytes.fromhex(body)
    except ValueError as e:
        raise ValueError(f"Invalid hex in type 7 value: {body!r}") from e
    return _xor(raw, seed).decode("latin-1")


def check(ciphertext: str, other: str) -> tuple[str, str, bool]:
    """Decode `ciphertext` and compare to `other`.

    Unlike the Juniper/HPE and Nokia ciphers, `other` is always treated as
    cleartext. A type 7 value carries no marker, and a real password can look
    exactly like one, so auto-detecting a second encoded value would guess.

    Returns (plain_a, plain_b, match).
    """
    plain_a = decrypt(ciphertext)
    return plain_a, other, plain_a == other
