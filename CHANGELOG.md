# Changelog

All notable changes to this project are documented here. This covers both the Python package and the website under `web/`. The website carries no version of its own: it deploys continuously to Cloudflare Pages on every push to `master`, so its changes are recorded under the package release they shipped alongside.

## Unreleased

### Changed

- Rebranded the Juniper vendor name to **Juniper/HPE** across the docs and website, following HPE's acquisition of Juniper. The code API (module names, CLI subcommands, URLs, env vars) is unchanged.

## v0.1.1 - 2026-07-23

### Fixed

- The sdist no longer ships the `web/` site. Now that the repo also hosts the Svelte app, the existing `include` list did not keep it out, so 138 unrelated files would have been packaged; `web/` is now excluded explicitly. The published v0.1.0 predates the merge and is unaffected.

### Changed

- The website moved into this repo under `web/`, alongside the Python package, so the known-answer vectors that both the Python and TypeScript implementations are tested against live in one place. History was preserved with `git subtree`. This also let the Cloudflare Pages project take the name `network-secret`, dropping the `-website` suffix from the URL.
- The browser version moved to [network-secret.pages.dev](https://network-secret.pages.dev/); the README link was updated to match.
- Renamed the site from "Network Secret Decoder" to **Network Secret**: it encodes as well as decodes, so "decoder" undersold it. Updates the browser title, the header brand, and the accessible label.
- Renamed the site's npm package from `network-secret-website` to `network-secret-web`.

### Docs

- README: added tests, PyPI, Python versions, and licence badges.

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

## Website releases before the merge

The site was developed in its own repository (`network-secret-decoder`, later `network-secret-website`) and carried its own version numbers until it moved into `web/` in v0.1.1 above. Those releases are kept here for the record; the site has not been versioned separately since.

### Site v0.2.0 - 2026-07-22

- Add a **Nokia `hash3`** explainer page (`/hash3`): SR OS 26.7+ primary-secret encryption for configuration secrets. Documented rather than decodable, because reproducing a value offline needs key material lifted out of the SR OS binary plus a per-configuration-leaf-key salt. Covers the construction (PBKDF2-HMAC-SHA3-512 + AES-256-GCM), the per-leaf-key salt, the wire format, setup commands, and security takeaways.
- Add a **Nokia `hash2`** explainer page (`/hash2`): the SR OS default reversible obfuscation. Documented rather than hosted as a decoder, because reversing it relies on a fixed key embedded in the SR OS software that we deliberately do not publish. Covers the `SHA-256` tag, the per-leaf-key salt, the fixed-key AES-256-CTR stream, and why the in-clear tag makes weak secrets recoverable by dictionary attack.
- Add a **Nokia `hash`** explainer page (`/hash`): the oldest SR OS format, the same construction as hash2 but **unsalted** (`IV = V`), making it the weakest of the four - one copy of the embedded key decodes any value with no config context. Kept doc-only for the same key-exposure reason, and notes that the missing salt does not make the master key any easier to recover (a known plaintext yields only an AES known-plaintext pair).

### Site v0.1.0 - 2026-06-16

- Initial release of the site: a static, fully client-side toolkit to decode and encode network device secrets. Nothing typed is ever sent to a server.
