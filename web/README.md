# Network Secret - website

A static, **fully client-side** toolkit to decode and encode network device secret formats. Every byte of computation happens in your browser - nothing is ever sent to a server - so it deploys to any static host (built for **Cloudflare Pages**).

Formats:

| #  | Format        | Vendor      | Kind                                 | Key             |
|----|---------------|-------------|--------------------------------------|-----------------|
| 01 | `$9$`         | Juniper     | reversible obfuscation               | none            |
| 02 | `$8$`         | Juniper     | AES-256-GCM authenticated encryption | master password |
| 03 | `custom-hash` | Nokia SR OS | AES-ECB + PKCS#7 (deterministic)     | shared AES key  |

One page per format. Adding a converter is one module (see [Adding a converter](#adding-a-converter)).

There are also three **explainer pages** for the Nokia hash family (documentation only, not converters, because reversing them needs a key embedded in the SR OS software that we deliberately do not publish):

- `/hash` - Nokia SR OS `hash`: the oldest format, the same construction as hash2 but unsalted (`IV = V`), hence the weakest. One copy of the embedded key decodes any value with no config context.
- `/hash2` - Nokia SR OS `hash2`: the default reversible obfuscation. Explains the `SHA-256` tag, the per-leaf-key salt, and the fixed-key AES-256-CTR stream.
- `/hash3` - Nokia SR OS `hash3` (26.7+ primary-secret encryption). Reproducing a value offline needs key material lifted out of the SR OS binary plus a per-configuration-leaf-key salt. Covers the construction (PBKDF2-HMAC-SHA3-512 + AES-256-GCM), the per-leaf-key salt, and the wire format.

## Stack

- **Svelte 5 + Vite + TypeScript**, no UI framework runtime beyond Svelte.
- **Vitest** for the crypto unit tests.
- Fonts (**Hanken Grotesk**, **JetBrains Mono**) are self-hosted via `@fontsource` - no external CDN.
- `$8$` uses the browser-native **Web Crypto API** (PBKDF2 + AES-256-GCM). `$9$` is a pure-TS port of the public algorithm. Nokia `custom-hash` uses AES-ECB, which Web Crypto deliberately omits, so it uses the small pure-JS **`aes-js`** library (bundled locally, no CDN).

## Develop

```bash
npm install
npm run dev       # http://localhost:5173
npm test          # Vitest: crypto unit tests + known-answer vectors
npm run check     # svelte-check (types)
npm run build     # -> dist/ (static, deployable)
npm run preview   # serve the production build locally
```

## Architecture

```text
src/
  lib/
    base64.ts              # base64 helpers (shared by $8$)
    router.ts              # tiny History-API router (path store + link action)
    explainers.ts          # documentation-only entries (metadata + prose component)
    ciphers/
      types.ts             # Cipher + Explainer contracts, catalogue types
      juniper9.ts          # $9$  (pure TS)            + tests
      juniper8.ts          # $8$  (Web Crypto)         + tests
      nokia-custom-hash.ts # custom-hash (aes-js, ECB)  + tests
      registry.ts          # assembles the catalogue (converters + explainers)
  components/
    Home.svelte            # hero + catalogue, generated from the catalogue
    CipherPage.svelte      # generic per-converter page (converter + notes)
    ExplainerPage.svelte   # generic explainer layout + prose styling
    explainers/            # prose bodies (content only) for the explainers
    Converter.svelte       # encode/decode UI, driven by a Cipher
    Header / Footer / Badge / CopyButton
```

The catalogue holds two kinds of entry: **converters** (interactive `Cipher` modules) and **explainers** (documentation-only pages for formats we deliberately do not decode here). `registry.ts` assembles both into one `catalogue`, stamping each with a `kind` and a derived two-digit index. The home cards, nav tabs, routes, pages, and titles are all generated from it. Every entry lives at a **top-level path** `/<id>` (e.g. `/juniper8`, `/hash2`) - there is no `/c/` prefix; unknown paths 404 client-side. The `public/_redirects` file gives Cloudflare Pages the SPA fallback so deep links resolve to `index.html`.

### Adding a converter

1. Create `src/lib/ciphers/<id>.ts` exporting a `Cipher` (implement `encode` and `decode`, fill in the metadata, set `status: "available"`; the index is derived, don't set one).
2. Add it to the `ciphers` array in `src/lib/ciphers/registry.ts`.
3. Add `src/lib/ciphers/<id>.test.ts` with known-answer vectors and a round-trip test.

The home card, the `/<id>` page, and the header tab all appear automatically. An entry can also be marked `status: "planned"` to show as a teaser before its `encode`/`decode` are implemented.

### Adding an explainer

1. Create the prose body `src/components/explainers/<Name>.svelte` (content only, no layout or styles - `ExplainerPage` supplies both).
2. Add an `Explainer` entry (metadata + `component`) to `src/lib/explainers.ts`.
