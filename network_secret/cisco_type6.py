"""Cisco IOS / IOS-XE type 6 encrypted secrets.

Type 6 is reversible authenticated encryption, keyed by the device master key
set with ``key config-key password-encrypt``. IOS uses it for secrets it must
recover in cleartext: BGP, RADIUS and TACACS keys. Without the master key a
type 6 value cannot be recovered.

    md5       = MD5(master key)                       -> a 16-byte AES-128 key
    ke        = AES-128-ECB(md5, salt || 00*7 || 01)  -> encrypts the secret
    ka        = AES-128-ECB(md5, salt || 00*8)        -> authenticates it
    block j   = AES-128-ECB(ke, 16 zero bytes with byte[3] = j)
    ciphertext= (plaintext || 00) XOR the block stream
    mac       = HMAC-SHA1(ka, ciphertext)[:4]
    output    = base41(salt || ciphertext || mac)

Note the trailing NUL byte. IOS encrypts and authenticates ``len + 1`` bytes,
because it hands the C string's NUL terminator to the cipher. Cisco's C
reference does this (``ios_encrypt_password.c`` loops ``i <= pass_len``). The
``encode6.py`` script in the same repository does not, so that script round
trips against itself but does not reproduce what a device emits. This module
follows the C reference and is byte-exact against Cisco's published vector.

Reference: https://github.com/CiscoDevNet/Type-6-Password-Encode

Public API:
    encrypt(plaintext: str, master_key: str, salt: bytes | None = None) -> str
    decrypt(ciphertext: str, master_key: str) -> str
    check(ciphertext: str, other: str, master_key: str) -> tuple[str, str, bool]
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = ["decrypt", "encrypt", "check"]

# Environment variable the CLI reads the master key from when --master is not
# given on the command line.
ENV_MASTER_KEY = "CISCO_MASTER_KEY"

# The 41 printable characters that follow ASCII 'A'.
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghi"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}
BASE = 41
GROUP = 3  # base41 symbols per 2-byte pair
_MAX_PAIR = 0xFFFF

SALT_LEN = 8  # bytes
MAC_LEN = 4  # bytes of the HMAC-SHA1 tag that are kept
BLOCK = 16  # AES block size in bytes
_COUNTER_BYTE = 3  # the keystream counter lives in byte 3 of the block
# The counter is one byte, so the stream tops out at 256 blocks. One byte of
# the payload is the NUL terminator, so the plaintext gets one less.
MAX_PLAINTEXT_LEN = 256 * BLOCK - 1
_MIN_RAW_LEN = SALT_LEN + 1 + MAC_LEN


def _b41_encode(data: bytes) -> str:
    """Encode bytes as base41: 2 bytes per 3 symbols, plus one pad group.

    The pad group carries the odd trailing byte when the input length is odd,
    and the marker (0x00, 0x01) when it is even.
    """
    pad = bytes([data[-1], 0x00]) if len(data) % 2 else b"\x00\x01"
    pairs = [data[i : i + 2] for i in range(0, len(data) - len(data) % 2, 2)]
    pairs.append(pad)
    out: list[str] = []
    for pair in pairs:
        n = int.from_bytes(pair, "big")
        out.append(
            ALPHABET[n // (BASE * BASE)] + ALPHABET[(n // BASE) % BASE] + ALPHABET[n % BASE]
        )
    return "".join(out)


def _b41_decode(text: str) -> bytes:
    """Decode base41 text, dropping the trailing pad group."""
    if not text:
        raise ValueError("Empty type 6 value")
    if len(text) % GROUP:
        raise ValueError(
            f"Malformed type 6 value: length {len(text)} is not a multiple of {GROUP}"
        )
    out = bytearray()
    for i in range(0, len(text), GROUP):
        group = text[i : i + GROUP]
        n = 0
        for ch in group:
            if ch not in _INDEX:
                raise ValueError(
                    f"Character {ch!r} is not in the type 6 base41 alphabet"
                )
            n = n * BASE + _INDEX[ch]
        if n > _MAX_PAIR:
            raise ValueError(
                f"Group {group!r} decodes to {n}, which does not fit in two bytes"
            )
        out += n.to_bytes(2, "big")
    # The final group is the pad. A non-zero last byte marks the (0x00, 0x01)
    # even-length form, so drop both bytes; otherwise keep the carried byte.
    return bytes(out[:-2] if out[-1] else out[:-1])


def _aes_ecb_block(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _subkeys(master_key: str, salt: bytes) -> tuple[bytes, bytes]:
    """Return (ke, ka): the encryption key and the authentication key."""
    # MD5 here is a key derivation step defined by IOS, not a digest relied on
    # for security. usedforsecurity=False keeps this working on a FIPS build.
    md5 = hashlib.md5(master_key.encode("utf-8"), usedforsecurity=False).digest()
    ke = _aes_ecb_block(md5, salt + b"\x00" * 7 + b"\x01")
    ka = _aes_ecb_block(md5, salt + b"\x00" * 8)
    return ke, ka


def _keystream_xor(ke: bytes, data: bytes) -> bytes:
    """XOR data with the counter-mode keystream. Its own inverse."""
    out = bytearray()
    block = b""
    for i, byte in enumerate(data):
        if i % BLOCK == 0:
            counter = bytearray(BLOCK)
            counter[_COUNTER_BYTE] = i // BLOCK
            block = _aes_ecb_block(ke, bytes(counter))
        out.append(byte ^ block[i % BLOCK])
    return bytes(out)


def _mac(ka: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(ka, ciphertext, hashlib.sha1).digest()[:MAC_LEN]


def encrypt(plaintext: str, master_key: str, salt: bytes | None = None) -> str:
    """Encrypt plaintext into a Cisco type 6 value under master_key.

    Output is non-deterministic: a fresh random salt is drawn on every call,
    so the same plaintext produces a different value each time. All of them
    decrypt back to the same plaintext with the same master key. Pass `salt`
    only to reproduce a known value, as the tests do.
    """
    if len(plaintext.encode("utf-8")) > MAX_PLAINTEXT_LEN:
        raise ValueError(
            f"Plaintext is too long for type 6: at most {MAX_PLAINTEXT_LEN} bytes"
        )
    if salt is None:
        salt = os.urandom(SALT_LEN)
    elif len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be {SALT_LEN} bytes; got {len(salt)}")
    ke, ka = _subkeys(master_key, salt)
    # The trailing NUL is part of the encrypted and authenticated data.
    ciphertext = _keystream_xor(ke, plaintext.encode("utf-8") + b"\x00")
    return _b41_encode(salt + ciphertext + _mac(ka, ciphertext))


def decrypt(ciphertext: str, master_key: str) -> str:
    """Decrypt a Cisco type 6 value with master_key.

    Raises ValueError on a malformed value or on authentication failure
    (wrong master key, or a value not produced by this scheme).
    """
    raw = _b41_decode(ciphertext.strip())
    if len(raw) < _MIN_RAW_LEN:
        raise ValueError(
            "Malformed type 6 value: too short to hold a salt, a secret and a MAC"
        )
    salt, body, mac = raw[:SALT_LEN], raw[SALT_LEN:-MAC_LEN], raw[-MAC_LEN:]
    ke, ka = _subkeys(master_key, salt)
    if not hmac.compare_digest(_mac(ka, body), mac):
        raise ValueError(
            "Authentication failed: wrong master key, or the value was not "
            "produced by this scheme"
        )
    decrypted = _keystream_xor(ke, body)
    # encrypt() appends exactly one NUL, so remove exactly one. rstrip() would
    # eat a NUL that is genuinely part of the plaintext, and an unconditional
    # slice would chop a real byte off a value written without the terminator.
    if decrypted.endswith(b"\x00"):
        decrypted = decrypted[:-1]
    try:
        return decrypted.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(
            "Decryption produced invalid UTF-8: wrong master key, or a corrupt value"
        ) from e


def check(ciphertext: str, other: str, master_key: str) -> tuple[str, str, bool]:
    """Decrypt `ciphertext` and compare to `other`.

    Unlike the Juniper/HPE and Nokia ciphers, `other` is always treated as
    cleartext. A type 6 value is bare base41 text with no marker, so
    auto-detecting a second encrypted value would guess.

    Returns (plain_a, plain_b, match).
    """
    plain_a = decrypt(ciphertext, master_key)
    return plain_a, other, plain_a == other
