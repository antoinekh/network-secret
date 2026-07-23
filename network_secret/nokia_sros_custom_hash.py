"""Nokia SR OS custom-hash secrets.

Configured on SR OS via:
    admin system security hash-control custom-hash algorithm aes256 key "..."

It is deterministic AES in ECB mode with PKCS#7 padding, base64-encoded, and
carried in config as "<base64> custom". Because ECB is deterministic, the same
plaintext and key produce identical ciphertext on every node sharing the key -
which is the point: portable, node-independent secrets.

The key is the literal characters of the shared-key string (SR OS counts the
string length, not a decoded byte length). 16 / 24 / 32 characters select
AES-128 / AES-192 / AES-256.

Public API:
    encrypt(plaintext: str, key: str) -> str
    decrypt(ciphertext: str, key: str) -> str
    check(ciphertext: str, other: str, key: str) -> tuple[str, str, bool]
"""

from __future__ import annotations

import base64
import binascii

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

__all__ = ["encrypt", "decrypt", "check"]

SUFFIX = "custom"
# Environment variable the CLI reads the shared key from when -k/--key is absent.
ENV_KEY = "SROS_CUSTOM_HASH_KEY"
BLOCK = 16  # AES block size in bytes
# SR OS writes the marker as exactly "<base64> custom": one space before the
# word. Matching is case-insensitive; surrounding whitespace is trimmed.
_MARKER = f" {SUFFIX}"


def _has_suffix(value: str) -> bool:
    return value.strip().lower().endswith(_MARKER)


def _strip_suffix(value: str) -> str:
    value = value.strip()
    if _has_suffix(value):
        value = value[: -len(_MARKER)]
    return value.strip()


def _key_bytes(key: str) -> bytes:
    raw = key.encode("utf-8")
    if len(raw) not in (16, 24, 32):
        raise ValueError(
            f"Key must be 16, 24, or 32 characters (AES-128 / AES-192 / AES-256); "
            f"got {len(raw)}"
        )
    return raw


def _ecb(key: str) -> Cipher:
    return Cipher(algorithms.AES(_key_bytes(key)), modes.ECB())


def encrypt(plaintext: str, key: str) -> str:
    """Encrypt plaintext into a Nokia custom-hash value: '<base64> custom'."""
    padder = PKCS7(BLOCK * 8).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    encryptor = _ecb(key).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return f"{base64.b64encode(ciphertext).decode('ascii')} {SUFFIX}"


def decrypt(ciphertext: str, key: str) -> str:
    """Decrypt a Nokia custom-hash value, with or without the ' custom' suffix.

    Raises ValueError on a malformed value, a bad key length, a wrong key, or
    a value not produced by this scheme.
    """
    b64 = _strip_suffix(ciphertext)
    try:
        raw = base64.b64decode(b64, validate=True)
    except binascii.Error as e:
        raise ValueError(f"Invalid base64 in custom-hash value: {b64!r}") from e
    if len(raw) == 0 or len(raw) % BLOCK != 0:
        raise ValueError(
            "Invalid ciphertext: length is not a multiple of the AES block size"
        )
    decryptor = _ecb(key).decryptor()
    decrypted = decryptor.update(raw) + decryptor.finalize()
    try:
        unpadder = PKCS7(BLOCK * 8).unpadder()
        plaintext = unpadder.update(decrypted) + unpadder.finalize()
        return plaintext.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(
            "Decryption failed: wrong key, or not a valid custom-hash value"
        ) from e


def check(ciphertext: str, other: str, key: str) -> tuple[str, str, bool]:
    """Decrypt `ciphertext` and compare to `other`.

    `other` may be a plaintext, or another custom-hash value (auto-detected by
    the ' custom' suffix and decrypted with the same key). Returns
    (plain_a, plain_b, match).
    """
    plain_a = decrypt(ciphertext, key)
    plain_b = decrypt(other, key) if _has_suffix(other) else other
    return plain_a, plain_b, plain_a == plain_b
