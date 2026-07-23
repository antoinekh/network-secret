"""network-secret: encode, decode, and check network device secrets.

Supported ciphers (one module each):
    juniper9                - Juniper $9$ reversible obfuscation (keyless)
    juniper8                - Juniper $8$ AES-256-GCM (master-password keyed)
    nokia_sros_custom_hash  - Nokia SR OS custom-hash AES-ECB (shared-key)

    >>> from network_secret import juniper8, juniper9, nokia_sros_custom_hash
"""

from __future__ import annotations

from importlib.metadata import version

from . import juniper8, juniper9, nokia_sros_custom_hash

__version__ = version("network-secret")

__all__ = [
    "juniper8",
    "juniper9",
    "nokia_sros_custom_hash",
    "__version__",
]
