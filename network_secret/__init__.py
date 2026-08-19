"""network-secret: encode, decode, and check network device secrets.

Supported formats (one module each):
    juniper9                    - Juniper/HPE $9$ reversible obfuscation (keyless)
    juniper8                    - Juniper/HPE $8$ AES-256-GCM (master-password keyed)
    juniper_encrypted_password  - Juniper/HPE $5$/$6$ SHA-crypt password hash (one-way)
    nokia_sros_custom_hash      - Nokia SR OS custom-hash AES-ECB (shared-key)
    nokia_sros_password         - Nokia SR OS $2y$ bcrypt password hash (one-way)
    cisco_type6                 - Cisco IOS type 6 AES + HMAC (master-key keyed)
    cisco_type7                 - Cisco IOS type 7 XOR obfuscation (keyless)
    cisco_type8                 - Cisco IOS type 8 PBKDF2-SHA256 hash (one-way)
    cisco_type9                 - Cisco IOS type 9 scrypt hash (one-way)

    >>> from network_secret import cisco_type7, juniper9

Cisco type 8, Cisco type 9, Nokia SR OS password, and Juniper/HPE
encrypted-password are one-way. Their encrypt() hashes, their check()
verifies a password, and their decrypt() raises.
"""

from __future__ import annotations

from importlib.metadata import version

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

__version__ = version("network-secret")

__all__ = [
    "cisco_type6",
    "cisco_type7",
    "cisco_type8",
    "cisco_type9",
    "juniper8",
    "juniper9",
    "juniper_encrypted_password",
    "nokia_sros_custom_hash",
    "nokia_sros_password",
    "__version__",
]
