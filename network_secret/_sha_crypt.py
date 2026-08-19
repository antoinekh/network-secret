"""Shared SHA-crypt implementation for the "$5$"/"$6$" password formats.

"$5$" (sha256-crypt) and "$6$" (sha512-crypt) are the same algorithm
parameterised only by which hash function feeds it, so it is implemented once
here and passed a hash name, exactly as `_cisco_hash.py` shares framing
between Cisco type 8 and type 9 and takes a KDF.

Spec: Ulrich Drepper, "Unix crypt using SHA-256 and SHA-512"
(https://www.akkadia.org/drepper/SHA-crypt.txt). The digest is produced by a
long chain of intermediate hashes (digests A/B/DP/DS feeding a `rounds`-long
loop over digest C), then encoded with a base64 variant unrelated to
standard base64 or to Cisco's variant in `_cisco_hash.py`: 3-byte groups
become 4 characters using little-endian bit order within the group, and the
byte that fills each of the three group positions is picked by a shuffled,
variant-specific permutation rather than taken in sequence. Both the
digest-chain logic and the permutation tables below were verified byte-for-
byte against `openssl passwd -5`/`-6` output, including custom `rounds=`
values (see tests/test_juniper_encrypted_password.py).

This module is internal: it is not exported from network_secret. It performs
no bounds checking on `rounds` - the caller (juniper_encrypted_password.py)
must enforce MIN_ROUNDS/MAX_ROUNDS before calling `hash_password`, since
`rounds` here is a plain multiplier on the amount of hashing work done.
"""

from __future__ import annotations

import hashlib
import secrets

ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
SALT_LEN = 16  # characters generated for a fresh salt

_DIGEST_SIZES = {"sha256": 32, "sha512": 64}

# Byte-index permutations feeding _b64_from_24bit(b2, b1, b0, n), taken from
# Drepper's reference sha256-crypt.c / sha512-crypt.c. Each 3-tuple names
# which digest byte fills the high/mid/low position of one 3-byte group.
_SHA256_GROUPS = [
    (0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
    (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29),
]
_SHA256_LAST = (None, 31, 30)  # final, partial group: 3 output characters

_SHA512_GROUPS = [
    (0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4),
    (47, 5, 26), (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51),
    (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13), (56, 14, 35),
    (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19),
    (62, 20, 41),
]
_SHA512_LAST = (None, None, 63)  # final, partial group: 2 output characters


def _b64_from_24bit(b2: int, b1: int, b0: int, n: int) -> str:
    """Encode one 3-byte group (b2 high, b0 low) as n base64 characters.

    Unlike standard base64, the 6-bit groups are emitted low-order first.
    """
    word = (b2 << 16) | (b1 << 8) | b0
    chars = []
    for _ in range(n):
        chars.append(ALPHABET[word & 0x3F])
        word >>= 6
    return "".join(chars)


def encode_digest(digest: bytes, hash_name: str) -> str:
    """Encode a raw sha256/sha512 digest with SHA-crypt's base64 variant."""
    if hash_name == "sha256":
        groups, last, last_n = _SHA256_GROUPS, _SHA256_LAST, 3
    elif hash_name == "sha512":
        groups, last, last_n = _SHA512_GROUPS, _SHA512_LAST, 2
    else:
        raise ValueError(f"Unsupported hash function: {hash_name!r}")
    out = [
        _b64_from_24bit(digest[b2], digest[b1], digest[b0], 4)
        for b2, b1, b0 in groups
    ]
    b2, b1, b0 = last
    out.append(
        _b64_from_24bit(
            0 if b2 is None else digest[b2],
            0 if b1 is None else digest[b1],
            digest[b0],
            last_n,
        )
    )
    return "".join(out)


def generate_salt(length: int = SALT_LEN) -> str:
    """Return a fresh `length`-character salt drawn from the crypt alphabet."""
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def hash_password(password: str, salt: str, rounds: int, hash_name: str) -> bytes:
    """Compute the raw SHA-crypt digest for `password`/`salt`/`rounds`.

    `rounds` is used exactly as given, with no bounds enforced here - see the
    module docstring.
    """
    digest_size = _DIGEST_SIZES[hash_name]
    pw = password.encode("utf-8")
    slt = salt.encode("ascii")

    ctx_a = hashlib.new(hash_name)
    ctx_a.update(pw)
    ctx_a.update(slt)

    ctx_b = hashlib.new(hash_name)
    ctx_b.update(pw)
    ctx_b.update(slt)
    ctx_b.update(pw)
    digest_b = ctx_b.digest()

    plen = len(pw)
    remaining = plen
    while remaining > digest_size:
        ctx_a.update(digest_b)
        remaining -= digest_size
    ctx_a.update(digest_b[:remaining])

    remaining = plen
    while remaining > 0:
        if remaining & 1:
            ctx_a.update(digest_b)
        else:
            ctx_a.update(pw)
        remaining >>= 1

    digest_a = ctx_a.digest()

    ctx_dp = hashlib.new(hash_name)
    for _ in range(plen):
        ctx_dp.update(pw)
    digest_dp = ctx_dp.digest()

    p_seq = bytearray()
    remaining = plen
    while remaining > digest_size:
        p_seq += digest_dp
        remaining -= digest_size
    p_seq += digest_dp[:remaining]
    p_bytes = bytes(p_seq)

    ctx_ds = hashlib.new(hash_name)
    for _ in range(16 + digest_a[0]):
        ctx_ds.update(slt)
    digest_ds = ctx_ds.digest()

    slen = len(slt)
    s_seq = bytearray()
    remaining = slen
    while remaining > digest_size:
        s_seq += digest_ds
        remaining -= digest_size
    s_seq += digest_ds[:remaining]
    s_bytes = bytes(s_seq)

    digest_c = digest_a
    for round_num in range(rounds):
        ctx_c = hashlib.new(hash_name)
        ctx_c.update(p_bytes if round_num % 2 else digest_c)
        if round_num % 3:
            ctx_c.update(s_bytes)
        if round_num % 7:
            ctx_c.update(p_bytes)
        ctx_c.update(digest_c if round_num % 2 else p_bytes)
        digest_c = ctx_c.digest()

    return digest_c
