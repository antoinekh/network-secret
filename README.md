# Network Secret Decoder

A static, **fully client-side** toolkit to decode and encode network device secret formats. Every byte of computation happens in your browser - nothing is ever sent to a server - so it deploys to any static host (built for **Cloudflare Pages**).

Formats:

| #  | Format        | Vendor      | Kind                                 | Key             |
|----|---------------|-------------|--------------------------------------|-----------------|
| 01 | `$9$`         | Juniper     | reversible obfuscation               | none            |
| 02 | `$8$`         | Juniper     | AES-256-GCM authenticated encryption | master password |
| 03 | `custom-hash` | Nokia SR OS | AES-ECB + PKCS#7 (deterministic)     | shared AES key  |

One page per format. Adding a format is one module (see [Adding a format](#adding-a-format)).

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
    ciphers/
      types.ts             # the Cipher contract (metadata + encode/decode)
      juniper9.ts          # $9$  (pure TS)            + tests
      juniper8.ts          # $8$  (Web Crypto)         + tests
      nokia-custom-hash.ts # custom-hash (aes-js, ECB)  + tests
      registry.ts          # the catalogue: one array
  components/
    Home.svelte            # hero + catalogue, generated from the registry
    CipherPage.svelte      # generic per-format page (converter + notes)
    Converter.svelte       # encode/decode UI, driven by a Cipher
    Header / Footer / Badge / CopyButton
```

The home cards and the per-format pages are generated from the `registry`. The router maps `/c/:id` to a registry entry; unknown paths 404 client-side. The `public/_redirects` file gives Cloudflare Pages the SPA fallback so deep links (e.g. `/c/juniper8`) resolve to `index.html`.

### Adding a format

1. Create `src/lib/ciphers/<id>.ts` exporting a `Cipher` (implement `encode` and `decode`, fill in the metadata, set `status: "available"`).
2. Register it in `src/lib/ciphers/registry.ts`.
3. Add `src/lib/ciphers/<id>.test.ts` with known-answer vectors and a round-trip test.

The home card, the `/c/<id>` page, and the header tab all appear automatically from the registry entry. An entry can also be marked `status: "planned"` to show as a teaser before its `encode`/`decode` are implemented.
