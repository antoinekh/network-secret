"""The catalogue of supported secret formats.

One Cipher entry per format. The CLI builds its subcommands and its --list
output entirely from this list; adding a format means adding a module and one
entry here.

Cisco type 8 and type 9 are one-way hashes. They keep the Cipher shape:
encrypt hashes, check verifies, and decrypt raises. Their names say so, so
--list shows it.
"""

from __future__ import annotations

from . import (
    cisco_type6,
    cisco_type7,
    cisco_type8,
    cisco_type9,
    juniper8,
    juniper9,
    juniper_encrypted_password,
    nokia_sros_custom_hash,
    nokia_sros_password,
)
from .types import Cipher, KeyKind

REGISTRY: list[Cipher] = [
    Cipher(
        id="juniper9",
        vendor="Juniper/HPE",
        name="Juniper/HPE $9$",
        key_kind=KeyKind.NONE,
        encrypt=juniper9.encrypt,
        decrypt=juniper9.decrypt,
        check=juniper9.check,
    ),
    Cipher(
        id="juniper8",
        vendor="Juniper/HPE",
        name="Juniper/HPE $8$",
        key_kind=KeyKind.MASTER_PASSWORD,
        encrypt=juniper8.encrypt,
        decrypt=juniper8.decrypt,
        check=juniper8.check,
        env_var=juniper8.ENV_MASTER,
    ),
    Cipher(
        id="juniper-encrypted-password",
        vendor="Juniper/HPE",
        name="Juniper/HPE encrypted-password (one-way)",
        key_kind=KeyKind.NONE,
        encrypt=juniper_encrypted_password.encrypt,
        decrypt=juniper_encrypted_password.decrypt,
        check=juniper_encrypted_password.check,
        variants=juniper_encrypted_password.VARIANTS,
    ),
    Cipher(
        id="nokia-sros-custom-hash",
        vendor="Nokia",
        name="Nokia SR OS custom-hash",
        key_kind=KeyKind.SHARED_KEY,
        encrypt=nokia_sros_custom_hash.encrypt,
        decrypt=nokia_sros_custom_hash.decrypt,
        check=nokia_sros_custom_hash.check,
        env_var=nokia_sros_custom_hash.ENV_KEY,
    ),
    Cipher(
        id="nokia-sros-password",
        vendor="Nokia",
        name="Nokia SR OS password (one-way)",
        key_kind=KeyKind.NONE,
        encrypt=nokia_sros_password.encrypt,
        decrypt=nokia_sros_password.decrypt,
        check=nokia_sros_password.check,
    ),
    Cipher(
        id="cisco-type6",
        vendor="Cisco",
        name="Cisco IOS type 6",
        key_kind=KeyKind.MASTER_PASSWORD,
        encrypt=cisco_type6.encrypt,
        decrypt=cisco_type6.decrypt,
        check=cisco_type6.check,
        env_var=cisco_type6.ENV_MASTER_KEY,
    ),
    Cipher(
        id="cisco-type7",
        vendor="Cisco",
        name="Cisco IOS type 7",
        key_kind=KeyKind.NONE,
        encrypt=cisco_type7.encrypt,
        decrypt=cisco_type7.decrypt,
        check=cisco_type7.check,
    ),
    Cipher(
        id="cisco-type8",
        vendor="Cisco",
        name="Cisco IOS type 8 (one-way)",
        key_kind=KeyKind.NONE,
        encrypt=cisco_type8.encrypt,
        decrypt=cisco_type8.decrypt,
        check=cisco_type8.check,
    ),
    Cipher(
        id="cisco-type9",
        vendor="Cisco",
        name="Cisco IOS type 9 (one-way)",
        key_kind=KeyKind.NONE,
        encrypt=cisco_type9.encrypt,
        decrypt=cisco_type9.decrypt,
        check=cisco_type9.check,
    ),
]


def find(cipher_id: str) -> Cipher | None:
    """Return the Cipher with this id, or None if there is no such cipher."""
    return next((c for c in REGISTRY if c.id == cipher_id), None)
