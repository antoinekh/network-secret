# Changelog

All notable changes to this project are documented here.

## v0.1.0 - 2026-07-23

### Added

- Initial release: unified `network-secret` package and CLI.
- Juniper `$9$` cipher (`network_secret.juniper9`), ported from `juniper9-crypt`.
- Juniper `$8$` cipher (`network_secret.juniper8`), ported from `juniper8-crypt`.
- Nokia SR OS custom-hash cipher (`network_secret.nokia_sros_custom_hash`), AES-ECB + PKCS#7 on `cryptography`, supporting 16/24/32-character keys.
- `network-secret` CLI with one subcommand per cipher, `--list`, and `--version`.
- GitHub Actions workflows: test matrix on Python 3.11-3.13, and a PyPI publish workflow on release.

### Fixed

- Juniper `$8$` decrypt now rejects iteration counts written with non-ASCII digits instead of failing with a generic parsing error.
