# Changelog

All notable changes to this project are documented here. This covers both the Python package and the website under `web/`. The website carries no version of its own: it deploys continuously to Cloudflare Pages on every push to `master`, so its changes are recorded under the package release they shipped alongside.

## Unreleased

### Added

- Juniper/HPE JUNOS `encrypted-password` (`network_secret.juniper_encrypted_password`, `juniper-encrypted-password`): a one-way Unix SHA-crypt hash for local user passwords, written in config as `encrypted-password "$5$salt$hash"; ## SECRET-DATA` (`$5$` sha256-crypt, `$6$` sha512-crypt). `$1$` (md5crypt), which older JUNOS wrote, is rejected by name rather than falling through to a generic parse failure. Accepts the value pasted straight out of a config line, quotes, trailing `;` and `## SECRET-DATA` marker included. An optional `rounds=N$` field is bounded to 1000-100000, mirroring how `juniper8` bounds its iteration count and the Nokia `$2y$` format bounds its bcrypt cost; a non-canonical value such as `rounds=007000` is accepted and echoed back verbatim by `--check`, while `--encrypt` always writes the canonical form, matching `openssl passwd`. No new dependency on either side: `hashlib` and Web Crypto already provide SHA-256/SHA-512.
- The website's Juniper/HPE `encrypted-password` converter, with Hash and Verify tabs and a one-way badge, next to the existing Juniper/HPE `$8$` converter.
- `juniper-encrypted-password` can now produce either SHA-crypt variant: `encrypt(plaintext, salt=None, variant=None)` takes `variant="sha512"` (the default, `$6$`, unchanged) or `variant="sha256"` (`$5$`); the CLI exposes this as `--variant {sha512,sha256}` on `--encrypt`, and the website as a selector in Hash mode. The mechanism is generic rather than hardcoded to this format: `Cipher` gained a `variants` field (`network_secret/types.py`, `web/src/lib/ciphers/types.ts`) that the CLI and `Converter.svelte` render whenever a format declares one. A `variant` argument and an explicitly `$5$`/`$6$`-prefixed `salt` argument are reconciled: they must agree, or `encrypt` raises `ValueError` naming both.

### Fixed

- The `--list` id column was a fixed 24 characters, so the new 26-character `juniper-encrypted-password` id overflowed it and broke row alignment. Column widths are now derived from the registry (`max(len(c.id) ...)`, `max(len(c.vendor) ...)`), so a future long id cannot silently misalign the table again.

## v0.3.0 - 2026-08-19

### Added

- Nokia SR OS password (`network_secret.nokia_sros_password`, `nokia-sros-password`): a one-way bcrypt hash for local user passwords, written in config as `$2y$10$<22-char salt><31-char digest>`. Verifies `$2a$`, `$2b$` and `$2y$` hashes alike, since they are the same algorithm under different historical tags, and always hashes to `$2y$`, matching what SR OS itself writes. The bcrypt cost read from a hash is bounded to 4-16, mirroring how `juniper8` bounds its iteration count.
- The website's Nokia SR OS password converter, with Hash and Verify tabs and a one-way badge, next to the existing Nokia custom-hash converter.
- New dependencies: `bcrypt>=4.0` (Python package) and `bcryptjs` (website).
- Python 3.14 is supported and covered by CI. The full suite passes on 3.14.5, and every format was exercised there against `cryptography` 49 and `bcrypt` 5.

### Security

- Updated `postcss` to 8.5.26 and `nanoid` to 3.3.18, clearing two high-severity advisories in build-only transitive dependencies of `vite`.

## v0.2.0 - 2026-08-19

### Added

- Cisco IOS type 6 (`network_secret.cisco_type6`, `cisco-type6`): reversible AES with an HMAC-SHA1 tag, keyed by the device master key, base41 armoured. Closes #2.
- Cisco IOS type 7 (`network_secret.cisco_type7`, `cisco-type7`): the legacy keyless XOR obfuscation. Closes #3.
- Cisco IOS type 8 (`network_secret.cisco_type8`, `cisco-type8`): a one-way PBKDF2-HMAC-SHA256 password hash, 20000 iterations. Closes #4.
- Cisco IOS type 9 (`network_secret.cisco_type9`, `cisco-type9`): a one-way scrypt password hash, N=16384 r=1 p=1. Closes #4.
- All four are verified against Cisco's own published test vectors, in both the Python package and the website.
- The website navigation is grouped by vendor. Each vendor opens a menu of its formats, so the bar stays readable now that it lists ten entries.
- Cisco type 6 follows Cisco's C reference, which encrypts and authenticates the secret's trailing NUL byte. The `encode6.py` script Cisco publishes beside it omits that byte, so it round-trips against itself but does not reproduce device output.
- A header link to the source repository, beside the theme toggle.
- The converter's Hash and Verify tabs for one-way formats, and the one-way badges on the catalogue card and the format page.

### Changed

- Rebranded the Juniper vendor name to **Juniper/HPE** across the docs and website, following HPE's acquisition of Juniper. The code API (module names, CLI subcommands, URLs, env vars) is unchanged.

### Fixed

- The CLI resolved a cipher's key environment variable by key kind, not by cipher. A second master-password cipher would have read `JUNOS_MASTER_PASSWORD`. Each registry entry now declares its own variable, so Cisco type 6 correctly reads `CISCO_MASTER_KEY`.
- The `--list` vendor column was 8 characters wide, so `Juniper/HPE` overflowed it. It is now 12.
- The website's Juniper/HPE `$9$` and `$8$` pages linked to the superseded `juniper9-crypt` and `juniper8-crypt` repositories. They now link to `network-secret`, and every format page carries the link.
- The lockfile recorded a stale project version: v0.1.1 bumped `pyproject.toml` but `uv.lock` still read 0.1.0. Refreshed it to match.
- The `--check` help text said "Decrypt and compare", which was wrong for a one-way hash; it now reads "Compare a value against a secret".
- The environment-variable constants (`ENV_MASTER`, `ENV_KEY`, `ENV_MASTER_KEY`) are now exported consistently from `__all__` in all three keyed modules (`juniper8`, `nokia_sros_custom_hash`, `cisco_type6`), instead of only the last one.
- On a narrow screen, hovering a vendor name in the site nav opened its menu, but moving the pointer down toward an item closed it again before it could be clicked. The gap between the trigger and the menu is now bridged so the pointer never leaves the hoverable area.
- The Python base41 encoder for Cisco type 6, `_b41_encode`, returned `"AAB"` for empty input, while the website's `b41Encode` raised `Error("Nothing to encode")`. Python now raises `ValueError("Nothing to encode")` too, matching the website's wording. Unreachable from the public API today, since `encrypt` always passes at least 13 bytes.
- `cisco_type8` and `cisco_type9` each defined a `MAGIC` constant that was never read: `_cisco_hash` rebuilt the same `$8$`/`$9$` prefix from a separate `type_number` argument, duplicating the same fact in two places. `_cisco_hash.format_hash`, `parse_hash`, `hash_password`, `verify` and `one_way_error` now take the `magic` prefix directly, so `MAGIC` is the single source of it and the modules match the `MAGIC` convention already used by `juniper8`/`juniper9`. Output is byte-identical, confirmed against the known-answer vectors.
- The website's hero sentence would have rendered "Secrets for undefined" for an empty catalogue, since `vendors[0]` is `undefined` when there are no vendors. Unreachable today because the catalogue is never empty, but `formatVendorList` (`web/src/components/vendor-list.ts`) now degrades to "network devices" in that case instead.

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
