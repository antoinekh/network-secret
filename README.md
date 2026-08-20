# network-secret

[![tests](https://github.com/antoinekh/network-secret/actions/workflows/test.yml/badge.svg)](https://github.com/antoinekh/network-secret/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/network-secret)](https://pypi.org/project/network-secret/)
[![Python versions](https://img.shields.io/pypi/pyversions/network-secret)](https://pypi.org/project/network-secret/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Encode, decode, and check network device secrets for Juniper/HPE JunOS, Nokia SR OS, and Cisco IOS, from the command line or Python. `network-secret` is a unified successor to `juniper8-crypt` and `juniper9-crypt`: it covers all nine formats in a single package with a single CLI.

> **Prefer a browser?** Decode, encode, hash and verify all nine formats at **[network-secret.pages.dev](https://network-secret.pages.dev/)**. It runs the same algorithms fully client-side - nothing you type is ever sent to a server.

## Repository layout

This repo holds both the Python package and the website that share these algorithms.

| Path | What |
|------|------|
| `network_secret/` | The Python package published to PyPI as `network-secret` |
| `tests/` | Python test suite |
| `web/` | The Svelte site deployed to Cloudflare Pages, with its own `README` and tests |

The two implementations share known-answer vectors, so keeping them in one repo means a cipher fix and its test data land in a single commit.

## Supported formats

| Format | CLI subcommand | Python module | Description |
|--------|---------------|---------------|-------------|
| `$9$` | `juniper9` | `network_secret.juniper9` | Juniper/HPE reversible obfuscation - keyless |
| `$8$` | `juniper8` | `network_secret.juniper8` | Juniper/HPE AES-256-GCM - keyed by master password |
| `$5$`/`$6$` | `juniper-encrypted-password` | `network_secret.juniper_encrypted_password` | Juniper/HPE JUNOS local-user encrypted-password (Unix SHA-crypt) - one-way |
| Nokia custom-hash | `nokia-sros-custom-hash` | `network_secret.nokia_sros_custom_hash` | Nokia SR OS AES-ECB shared-key cipher |
| `$2y$` | `nokia-sros-password` | `network_secret.nokia_sros_password` | Nokia SR OS bcrypt local user password hash - one-way |
| Type 6 | `cisco-type6` | `network_secret.cisco_type6` | Cisco IOS reversible AES + HMAC - keyed by the master key |
| Type 7 | `cisco-type7` | `network_secret.cisco_type7` | Cisco IOS legacy XOR obfuscation - keyless |
| `$8$` | `cisco-type8` | `network_secret.cisco_type8` | Cisco IOS PBKDF2-SHA256 password hash - one-way |
| `$9$` | `cisco-type9` | `network_secret.cisco_type9` | Cisco IOS scrypt password hash - one-way |

> **`$8$` and `$9$` mean two different things.** Juniper/HPE and Cisco both use these markers, for unrelated algorithms. A Juniper/HPE `$9$` is a keyless substitution cipher; a Cisco `$9$` is a scrypt password hash. Pick the subcommand by the device the value came from, not by the prefix. `network-secret` never guesses between them.

## Install

```bash
pip install network-secret
```

Or with `uv`:

```bash
uv add network-secret
```

## Python API

```python
from network_secret import juniper8, juniper9, juniper_encrypted_password, nokia_sros_custom_hash, nokia_sros_password

# Juniper/HPE $9$ (keyless)
cipher9 = juniper9.encrypt("BGPsecret1")
plain9 = juniper9.decrypt(cipher9)
# 'BGPsecret1'

# Juniper/HPE $8$ (master-password keyed)
master = "MyMasterPassword"
cipher8 = juniper8.encrypt("BGPsecret1", master)
plain8 = juniper8.decrypt(cipher8, master)
# 'BGPsecret1'
plain_a, plain_b, match = juniper8.check(cipher8, "BGPsecret1", master)
# match is True

# Juniper/HPE JUNOS encrypted-password (Unix SHA-crypt, one-way)
hash_jep = juniper_encrypted_password.encrypt("lab123")
# '$6$OxsofBL3v2.ckv5z$6cnGooSbcNVCY44cBYiK7Kh.5q.TSZm/71tQMzXc/55aHCY0muFlu7fwjpUlRYd8XjxKlYv4LP.yIMBl2ntOn0' (a fresh salt every call, always starting '$6$', the default variant)
hash_jep_sha256 = juniper_encrypted_password.encrypt("lab123", variant="sha256")
# '$5$9DQNhbbsWrky5BZ3$rfUMEf2WdGxGFHdPem4Z/Rj9hGOQKKbVcyuJ2H98eBA' (variant="sha256" produces "$5$" instead; VARIANTS is ("sha512", "sha256"), first entry is the default)
given, recomputed, match = juniper_encrypted_password.check(
    "$5$itHMToxg$IAeDKDuWsSCoL2W7fognCW8cyNj4YE9ZhDvCoWFC5y/", "lab123"
)
# match is True
juniper_encrypted_password.decrypt(hash_jep)
# ValueError: JUNOS encrypted-password values are a one-way SHA-crypt hash and cannot be decrypted. Use --check to test a password against one.
juniper_encrypted_password.encrypt("lab123", salt="$5$abcdefgh", variant="sha512")
# ValueError: variant='sha512' conflicts with salt='$5$abcdefgh': the salt's '$5$' prefix names a different format than variant 'sha512' ('$6$'); pass matching values, or only one of them

# Nokia SR OS custom-hash (16/24/32-character shared key)
key = "a3f8d9e112c04b7af1c3e8b92d057a4e"
cipher_nokia = nokia_sros_custom_hash.encrypt("BGPsecret1", key)
plain_nokia = nokia_sros_custom_hash.decrypt(cipher_nokia, key)
# 'BGPsecret1'
plain_a, plain_b, match = nokia_sros_custom_hash.check(cipher_nokia, "BGPsecret1", key)
# match is True

# Nokia SR OS password (bcrypt, one-way)
hash_nokia_pw = nokia_sros_password.encrypt("lab123")
# '$2y$10$.R0.1VcFPQhlLvMXR32acet62eX19GfoBlMYJo7ae.y8ijmg3cAa6' (a fresh salt every call, always starting '$2y$')
given, recomputed, match = nokia_sros_password.check("$2y$10$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe", "lab123")
# match is True
given, recomputed, match = nokia_sros_password.check("$2b$10$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe", "lab123")
# match is True too: "$2a$", "$2b$" and "$2y$" are the same algorithm, only the tag differs
nokia_sros_password.decrypt(hash_nokia_pw)
# ValueError: Nokia SR OS passwords are bcrypt hashes and cannot be decrypted. Use --check to test a password against one.

# Cisco IOS type 7 (keyless, legacy obfuscation)
from network_secret import cisco_type6, cisco_type7, cisco_type8, cisco_type9

cipher7 = cisco_type7.encrypt("BGPsecret1")
plain7 = cisco_type7.decrypt(cipher7)
# 'BGPsecret1'

# Cisco IOS type 6 (master-key keyed)
cipher6 = cisco_type6.encrypt("BGPsecret1", "MyMasterKey")
plain6 = cisco_type6.decrypt(cipher6, "MyMasterKey")
# 'BGPsecret1'

# Cisco IOS type 8 and type 9 are one-way hashes
hash8 = cisco_type8.encrypt("BGPsecret1")
given, recomputed, match = cisco_type8.check(hash8, "BGPsecret1")
# match is True
cisco_type8.decrypt(hash8)
# ValueError: Cisco type 8 is a one-way hash and cannot be decrypted. Use --check to test a password against it.
```

All nine `check()` functions return a `tuple[str, str, bool]`. For five of them the two strings are the decrypted plaintexts and whether they match. Juniper/HPE encrypted-password, Nokia SR OS password, Cisco type 8 and Cisco type 9 cannot decrypt anything, so they return the hash you passed in, the hash recomputed from the candidate password, and whether those match. For Cisco type 6 and type 7, the second argument to `check()` is always read as cleartext, because neither format carries a marker that tells it apart from a password.

## Command-line usage

```bash
# List all supported ciphers
network-secret --list

# Show the version
network-secret --version
```

### Juniper/HPE `$9$` (keyless)

```bash
network-secret juniper9 --encrypt 'BGPsecret1'
network-secret juniper9 --decrypt '$9$abc...'
network-secret juniper9 --check '$9$abc...' 'BGPsecret1'
```

### Juniper/HPE `$8$` (master-password keyed)

The master password is resolved in this order: `-m`/`--master` flag, then the `JUNOS_MASTER_PASSWORD` environment variable, then an interactive no-echo prompt.

```bash
# Master on the command line
network-secret juniper8 -m 'MyMaster' --encrypt 'BGPsecret1'
network-secret juniper8 -m 'MyMaster' --decrypt '$8$aes256-gcm$...'
network-secret juniper8 -m 'MyMaster' --check '$8$aes256-gcm$...' 'BGPsecret1'

# Master from the environment (keeps it out of shell history and the process list)
export JUNOS_MASTER_PASSWORD='MyMaster'
network-secret juniper8 --decrypt '$8$aes256-gcm$...'

# Master from an interactive prompt
network-secret juniper8 --decrypt '$8$aes256-gcm$...'
# Master password: <typed without echo>
```

> Always quote `$8$` and `$9$` strings with single quotes - the shell expands `$8` and `$9` as positional parameters otherwise.

### Juniper/HPE JUNOS encrypted-password (`$5$`/`$6$`, one-way)

JUNOS stores local user passwords as standard Unix SHA-crypt, written in config as `encrypted-password "$5$salt$hash"; ## SECRET-DATA` (`$5$` is sha256-crypt, `$6$` is sha512-crypt). There is nothing to decrypt, so `--encrypt` hashes with a fresh random salt and `--check` verifies a candidate password by reusing the salt, variant, and round count carried in the value you give it. `$1$` (md5crypt), which older JUNOS wrote, is deliberately not supported and is rejected by name.

```bash
network-secret juniper-encrypted-password --encrypt 'lab123'
network-secret juniper-encrypted-password --check '$5$itHMToxg$IAeDKDuWsSCoL2W7fognCW8cyNj4YE9ZhDvCoWFC5y/' 'lab123'

network-secret juniper-encrypted-password --decrypt '$6$OV3tvDvc$QT3FzP8LWnxLDCfDLKibn1.EzGS5crupCiea7Kbi2W4Y9Z1kYu9EYTxs/z344U8Mwh4QtwlnbUiLZWUHyhrZl1'
# error: JUNOS encrypted-password values are a one-way SHA-crypt hash and cannot be decrypted. Use --check to test a password against one.
```

You can paste the value straight out of a JUNOS config, quotes, trailing `;` and `## SECRET-DATA` marker included, rather than trimming it down to the bare `$5$.../$6$...` value first:

```bash
network-secret juniper-encrypted-password --check '"$5$itHMToxg$IAeDKDuWsSCoL2W7fognCW8cyNj4YE9ZhDvCoWFC5y/"; ## SECRET-DATA' 'lab123'
```

`--encrypt` picks the hash variant with `--variant {sha512,sha256}`, defaulting to `sha512` (`$6$`), which is what current JUNOS writes when `set system login password format sha512` is configured; `--variant sha256` instead produces what `set system login password format sha256` writes (`$5$`). This is a convenience for matching a device's existing style, not a correctness requirement: JUNOS `encrypted-password` accepts any crypt hash you paste regardless of the device's `password format` setting, which only governs what the device itself generates from a plaintext. A `$6$` hash produced here (or by any other tool) works on a device set to `sha256` just as well, and vice versa. `--variant` is only offered where it means something: it appears on `--encrypt`, and is silently ignored if given alongside `--check` or `--decrypt`, since neither of those picks a format to produce.

```bash
network-secret juniper-encrypted-password --encrypt 'lab123'
# $6$0W8cbt0LJgH4mTP/$sXjncyJQo/Hb0FLhvkcBota5gC6av4gUv2Vq2WmbHfMU1Q1mp47yqi5Oti8dNc9VPdjZaVRXOAn7AvqpwcCA/0

network-secret juniper-encrypted-password --variant sha256 --encrypt 'lab123'
# $5$wzkCmB9LIq8jselM$oTZKwaa/N7jImALIYZDkZ0inUPBIUGvRmXa1PUbKas5

network-secret juniper-encrypted-password --variant sha512 --encrypt 'lab123'
# $6$.ZENYvk9UOOJ.jkp$Oyxb6dC0wSym6yjjVbMcifgEABK4xhGRqTbF1WqzJtizGMJymEvfspjhomkvwS4ZwUNitqRWY4/A0QV7dgM7Q/
```

Rounds are bounded to 1000-100000 (`MIN_ROUNDS`/`MAX_ROUNDS` in `network_secret/juniper_encrypted_password.py`). Drepper's SHA-crypt spec permits a `rounds=N$` field up to 999,999,999, read from the value being checked, and JUNOS itself never emits anything but its 5000 default; without this bound a pasted hash could force arbitrarily expensive work and hang the tool, the same reasoning behind `juniper8`'s PBKDF2 iteration bound and the Nokia `$2y$` format's bcrypt cost bound.

### Nokia SR OS custom-hash (shared-key)

The shared key is resolved in this order: `-k`/`--key` flag, then the `SROS_CUSTOM_HASH_KEY` environment variable, then an interactive no-echo prompt. Keys must be exactly 16, 24, or 32 characters.

```bash
# Key on the command line
network-secret nokia-sros-custom-hash -k 'a3f8d9e112c04b7af1c3e8b92d057a4e' --encrypt 'BGPsecret1'
network-secret nokia-sros-custom-hash -k 'a3f8d9e112c04b7af1c3e8b92d057a4e' --decrypt 'ABC123...'
network-secret nokia-sros-custom-hash -k 'a3f8d9e112c04b7af1c3e8b92d057a4e' --check 'ABC123...' 'BGPsecret1'

# Key from the environment
export SROS_CUSTOM_HASH_KEY='a3f8d9e112c04b7af1c3e8b92d057a4e'
network-secret nokia-sros-custom-hash --decrypt 'ABC123...'
```

### Nokia SR OS password (bcrypt, one-way)

SR OS stores local user passwords as bcrypt, written in config as `$2y$10$<22-char salt><31-char digest>`. There is nothing to decrypt, so `--encrypt` hashes with a fresh random salt and `--check` verifies a candidate password against an existing hash by reusing that hash's salt.

```bash
network-secret nokia-sros-password --encrypt 'lab123'
network-secret nokia-sros-password --check '$2y$10$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe' 'lab123'

network-secret nokia-sros-password --decrypt '$2y$10$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe'
# error: Nokia SR OS passwords are bcrypt hashes and cannot be decrypted. Use --check to test a password against one.
```

`$2a$`, `$2b$` and `$2y$` are the same bcrypt algorithm under different historical tags, so `--check` accepts a hash carrying any of the three; `--encrypt` always emits `$2y$`, which is what SR OS itself writes.

### Cisco IOS type 6 (master-key keyed)

The master key is the one set with `key config-key password-encrypt`. It is resolved in this order: `-m`/`--master` flag, then the `CISCO_MASTER_KEY` environment variable, then an interactive no-echo prompt.

```bash
network-secret cisco-type6 -m 'MyMasterKey' --encrypt 'BGPsecret1'
network-secret cisco-type6 -m 'MyMasterKey' --decrypt 'NdUI^_YP[VEP...'
network-secret cisco-type6 -m 'MyMasterKey' --check 'NdUI^_YP[VEP...' 'BGPsecret1'

export CISCO_MASTER_KEY='MyMasterKey'
network-secret cisco-type6 --decrypt 'NdUI^_YP[VEP...'
```

### Cisco IOS type 7 (keyless)

```bash
network-secret cisco-type7 --encrypt 'BGPsecret1'
network-secret cisco-type7 --decrypt '060506324F41'
network-secret cisco-type7 --check '060506324F41' 'cisco'
```

Type 7 is obfuscation, not encryption. Anyone can decode it. Treat any type 7 value you find as cleartext.

### Cisco IOS type 8 and type 9 (one-way)

These are password hashes, so there is nothing to decrypt. `--encrypt` computes a hash with a fresh random salt, and `--check` tests a password against an existing hash by reusing that hash's salt.

```bash
network-secret cisco-type8 --encrypt 'BGPsecret1'
network-secret cisco-type8 --check '$8$J5J/1K3e8gk974$HRez...' 'cisco123'

network-secret cisco-type9 --encrypt 'BGPsecret1'
network-secret cisco-type9 --check '$9$ihSswXDbk0kaVK$o.uy...' 'cisco123'

network-secret cisco-type9 --decrypt '$9$ihSswXDbk0kaVK$o.uy...'
# error: Cisco type 9 is a one-way hash and cannot be decrypted. Use --check to test a password against it.
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (or `--check` matched) |
| 1 | `--check` mismatched |
| 2 | Invalid input (malformed value, wrong key, etc.) |

## Supersedes

`network-secret` supersedes the older single-format packages `juniper8-crypt` and `juniper9-crypt`. It exposes the same algorithms under the same function signatures (`encrypt`, `decrypt`, `check`); migrating is a matter of updating the import path.

## License

MIT
