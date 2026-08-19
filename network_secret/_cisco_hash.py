"""Framing shared by the Cisco IOS one-way password hashes.

Type 8 and type 9 use the same framing, the same salt rules and the same
output encoding. They differ only in the key derivation function, so
everything else lives here and the two public modules stay thin.

    $<type>$<salt>$<hash>

The salt is used as its raw ASCII bytes; it is never decoded first. The
32-byte digest is encoded with standard base64 bit order over Cisco's own
64-character alphabet, "./0-9A-Za-z", with no padding.

Reference: convert_bitstring.c, ios_hash_password.c and select_salt.c in
https://github.com/CiscoDevNet/Type-6-Password-Encode

This module is internal: it is not exported from network_secret.
"""

from __future__ import annotations

import base64
import hmac
import secrets
from collections.abc import Callable

# Cisco's alphabet, in the order used by convert_bitstring.c.
ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_TO_CISCO = str.maketrans(_STANDARD, ALPHABET)

DIGEST_LEN = 32  # bytes; 32 bytes encode to 43 characters
SALT_LEN = 14  # characters generated; 14 * 6 bits = 84 bits of entropy

# A KDF takes (password_bytes, salt_bytes) and returns DIGEST_LEN bytes.
Kdf = Callable[[bytes, bytes], bytes]


def encode_digest(digest: bytes) -> str:
    """Encode a digest with Cisco's base64 variant, without padding."""
    return base64.b64encode(digest).decode("ascii").rstrip("=").translate(_TO_CISCO)


def generate_salt() -> str:
    """Return a fresh 14-character salt drawn from Cisco's alphabet.

    `secrets` (not `random`) is used: unlike the reversible formats, these
    are password hashes, and a predictable salt weakens them.
    """
    return "".join(secrets.choice(ALPHABET) for _ in range(SALT_LEN))


def validate_salt(salt: str) -> str:
    """Return `salt` unchanged if IOS would accept it, else raise ValueError.

    IOS accepts printable ASCII other than space and '$' (validate_salt() in
    ios_hash_password.c). A '$' would break the field split and a space would
    break the config line. Length is not checked: IOS generates 14 characters
    but copies any given salt verbatim, so a device may carry another length.
    """
    if not salt:
        raise ValueError("Empty salt")
    for ch in salt:
        if ch == "$" or ch == " " or not ch.isascii() or not ch.isprintable():
            raise ValueError(f"Invalid character {ch!r} in salt {salt!r}")
    return salt


def format_hash(type_number: int, salt: str, digest: bytes) -> str:
    """Assemble a "$N$salt$hash" string."""
    return f"${type_number}${salt}${encode_digest(digest)}"


def parse_hash(value: str, type_number: int) -> tuple[str, str]:
    """Split a "$N$salt$hash" value into (salt, encoded_hash).

    Raises ValueError when the value is not a hash of this type.
    """
    magic = f"${type_number}$"
    text = value.strip()
    if not text.startswith(magic):
        raise ValueError(
            f"Not a Cisco type {type_number} hash: must start with {magic}"
        )
    # A leading '$' yields an empty first element.
    parts = text.split("$")
    if len(parts) != 4:
        raise ValueError(
            f"Malformed type {type_number} hash: expected $<type>$<salt>$<hash>"
        )
    _, _type, salt, encoded = parts
    validate_salt(salt)
    if not encoded:
        raise ValueError(f"Malformed type {type_number} hash: empty hash field")
    for ch in encoded:
        if ch not in ALPHABET:
            raise ValueError(
                f"Character {ch!r} is not in the Cisco base64 alphabet"
            )
    return salt, encoded


def hash_password(
    password: str, kdf: Kdf, type_number: int, salt: str | None = None
) -> str:
    """Hash `password` and return the full "$N$salt$hash" string."""
    salt = generate_salt() if salt is None else validate_salt(salt)
    digest = kdf(password.encode("utf-8"), salt.encode("ascii"))
    return format_hash(type_number, salt, digest)


def verify(
    hash_value: str, password: str, kdf: Kdf, type_number: int
) -> tuple[str, str, bool]:
    """Recompute `hash_value` from `password` and compare.

    The salt comes from `hash_value`, so the recomputed string differs only
    in the hash field. Returns (given, recomputed, match), which matches the
    Cipher.check contract.
    """
    salt, _encoded = parse_hash(hash_value, type_number)
    recomputed = hash_password(password, kdf, type_number, salt)
    given = hash_value.strip()
    return given, recomputed, hmac.compare_digest(given, recomputed)


def one_way_error(type_number: int) -> ValueError:
    """The error every one-way format raises from decrypt()."""
    return ValueError(
        f"Cisco type {type_number} is a one-way hash and cannot be decrypted. "
        f"Use --check to test a password against it."
    )
