# Changelog

## Unreleased

### Changed

- Moved the site into the [network-secret](https://github.com/antoinekh/network-secret) monorepo under `web/`, alongside the Python package. History was preserved via `git subtree`. This also lets the Cloudflare Pages project take the name `network-secret`, dropping the `-website` suffix from the URL.
- Renamed the site from "Network Secret Decoder" to **Network Secret**: the tool encodes as well as decodes, so "decoder" undersold it. Updates the browser title, the header brand, and the accessible label.
- Renamed the npm package from `network-secret-website` to `network-secret-web`.

## v0.2.0 - 2026-07-22

- Add a **Nokia `hash3`** explainer page (`/hash3`): SR OS 26.7+ primary-secret encryption for configuration secrets. Documented rather than decodable, because reproducing a value offline needs key material lifted out of the SR OS binary plus a per-configuration-leaf-key salt. Covers the construction (PBKDF2-HMAC-SHA3-512 + AES-256-GCM), the per-leaf-key salt, the wire format, setup commands, and security takeaways.
- Add a **Nokia `hash2`** explainer page (`/hash2`): the SR OS default reversible obfuscation. Documented rather than hosted as a decoder, because reversing it relies on a fixed key embedded in the SR OS software that we deliberately do not publish. Covers the `SHA-256` tag, the per-leaf-key salt, the fixed-key AES-256-CTR stream, and why the in-clear tag makes weak secrets recoverable by dictionary attack.
- Add a **Nokia `hash`** explainer page (`/hash`): the oldest SR OS format, the same construction as hash2 but **unsalted** (`IV = V`), making it the weakest of the four - one copy of the embedded key decodes any value with no config context. Kept doc-only for the same key-exposure reason, and notes that the missing salt does not make the master key any easier to recover (a known plaintext yields only an AES known-plaintext pair).

## v0.1.0 - 2026-06-16

- Initial release of **Network Secret Decoder**: a static, fully client-side toolkit to decode and encode network device secrets. Nothing typed is ever sent to a server.
