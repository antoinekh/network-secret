"""The catalogue of supported secret formats.

One Cipher entry per format. The CLI builds its subcommands and its --list
output entirely from this list; adding a format means adding a module and one
entry here.
"""

from __future__ import annotations

from . import juniper8, juniper9, nokia_sros_custom_hash
from .types import Cipher, KeyKind

REGISTRY: list[Cipher] = [
    Cipher(
        id="juniper9",
        vendor="Juniper",
        name="Juniper $9$",
        key_kind=KeyKind.NONE,
        encrypt=juniper9.encrypt,
        decrypt=juniper9.decrypt,
        check=juniper9.check,
    ),
    Cipher(
        id="juniper8",
        vendor="Juniper",
        name="Juniper $8$",
        key_kind=KeyKind.MASTER_PASSWORD,
        encrypt=juniper8.encrypt,
        decrypt=juniper8.decrypt,
        check=juniper8.check,
    ),
    Cipher(
        id="nokia-sros-custom-hash",
        vendor="Nokia",
        name="Nokia SR OS custom-hash",
        key_kind=KeyKind.SHARED_KEY,
        encrypt=nokia_sros_custom_hash.encrypt,
        decrypt=nokia_sros_custom_hash.decrypt,
        check=nokia_sros_custom_hash.check,
    ),
]


def find(cipher_id: str) -> Cipher | None:
    """Return the Cipher with this id, or None if there is no such cipher."""
    return next((c for c in REGISTRY if c.id == cipher_id), None)
