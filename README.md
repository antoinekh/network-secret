# network-secret

Encode, decode, and check network device secrets for Juniper JunOS and Nokia SR OS, from the command line or Python. `network-secret` is a unified successor to `juniper8-crypt` and `juniper9-crypt`: it covers all three formats in a single package with a single CLI.

> **Prefer a browser?** Encode and decode all three formats at **[network-secret-website.pages.dev](https://network-secret-website.pages.dev/)**. It runs the same algorithms fully client-side - nothing you type is ever sent to a server.

## Supported formats

| Format | CLI subcommand | Python module | Description |
|--------|---------------|---------------|-------------|
| `$9$` | `juniper9` | `network_secret.juniper9` | Juniper reversible obfuscation - keyless |
| `$8$` | `juniper8` | `network_secret.juniper8` | Juniper AES-256-GCM - keyed by master password |
| Nokia custom-hash | `nokia-sros-custom-hash` | `network_secret.nokia_sros_custom_hash` | Nokia SR OS AES-ECB shared-key cipher |

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
from network_secret import juniper8, juniper9, nokia_sros_custom_hash

# Juniper $9$ (keyless)
cipher9 = juniper9.encrypt("BGPsecret1")
plain9 = juniper9.decrypt(cipher9)
# 'BGPsecret1'

# Juniper $8$ (master-password keyed)
master = "MyMasterPassword"
cipher8 = juniper8.encrypt("BGPsecret1", master)
plain8 = juniper8.decrypt(cipher8, master)
# 'BGPsecret1'
plain_a, plain_b, match = juniper8.check(cipher8, "BGPsecret1", master)
# match is True

# Nokia SR OS custom-hash (16/24/32-character shared key)
key = "a3f8d9e112c04b7af1c3e8b92d057a4e"
cipher_nokia = nokia_sros_custom_hash.encrypt("BGPsecret1", key)
plain_nokia = nokia_sros_custom_hash.decrypt(cipher_nokia, key)
# 'BGPsecret1'
plain_a, plain_b, match = nokia_sros_custom_hash.check(cipher_nokia, "BGPsecret1", key)
# match is True
```

All three `check()` functions return a `tuple[str, str, bool]`: the two decrypted plaintexts and whether they match.

## Command-line usage

```bash
# List all supported ciphers
network-secret --list

# Show the version
network-secret --version
```

### Juniper `$9$` (keyless)

```bash
network-secret juniper9 --encrypt 'BGPsecret1'
network-secret juniper9 --decrypt '$9$abc...'
network-secret juniper9 --check '$9$abc...' 'BGPsecret1'
```

### Juniper `$8$` (master-password keyed)

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
