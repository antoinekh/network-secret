"""The Cipher contract shared by every supported secret format.

Mirrors the registry-of-ciphers structure of the network-secret-decoder web
app: each format is one Cipher entry carrying its metadata and its three
operations.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum


class KeyKind(Enum):
    """What kind of key a cipher needs (drives CLI key handling)."""

    NONE = "none"
    MASTER_PASSWORD = "master-password"
    SHARED_KEY = "shared-key"


@dataclass(frozen=True)
class Cipher:
    """A supported secret format and its operations.

    encrypt / decrypt / check are the module-level functions of the cipher.
    Their signatures vary by key_kind (keyless ciphers take no key argument),
    so they are typed loosely here; the CLI supplies the right arguments per
    key_kind.
    """

    id: str
    vendor: str
    name: str
    key_kind: KeyKind
    encrypt: Callable[..., str]
    decrypt: Callable[..., str]
    check: Callable[..., tuple[str, str, bool]]

    @property
    def keyed(self) -> bool:
        return self.key_kind is not KeyKind.NONE
