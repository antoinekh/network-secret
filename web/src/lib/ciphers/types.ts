/**
 * The contracts the catalogue is built from.
 *
 * A `Cipher` is an interactive converter (encode/decode in the browser). An
 * `Explainer` is a documentation-only page for a format we deliberately do not
 * decode here. Both are listed in `registry.ts`, which stamps each entry with a
 * `kind` and a two-digit `index` derived from its position. The home card, nav
 * tab, route, and page are all generated from that catalogue, so adding either
 * kind is a single registry entry - no component hardcodes a format.
 */

import type { Component } from "svelte";

export type CipherStatus = "available" | "planned";

export interface CipherLink {
  /** Link text (e.g. the repo path). */
  label: string;
  /** Destination URL. */
  url: string;
  /** Short description of what's there (e.g. "Python library & CLI"). */
  note?: string;
}

export interface CipherExample {
  /** Encoded value (the format's own string, e.g. a "$9$..." secret). */
  encoded: string;
  /** Cleartext the encoded value decodes to. */
  plaintext: string;
  /** Key/master password, for keyed formats. */
  key?: string;
}

export interface CipherInfo {
  /** URL-safe identifier, e.g. "juniper9". Also the top-level path (`/juniper9`). */
  id: string;
  /** Display name, e.g. "Juniper/HPE $9$". */
  name: string;
  /** Vendor, e.g. "Juniper/HPE". */
  vendor: string;
  /** Magic prefix, e.g. "$9$". */
  magic: string;
  /** One-line description. */
  tagline: string;
  /** Whether the format is reversible without a key (obfuscation vs encryption). */
  reversible: boolean;
  /** Whether a key/master password is required. */
  keyed: boolean;
  /** Label for the key field, when keyed. */
  keyLabel?: string;
  /** "available" formats are interactive; "planned" render as a teaser. */
  status: CipherStatus;
  /** Short explanatory bullets shown on the format page. */
  notes: string[];
  /** Optional worked example used by the "try it" chips. */
  example?: CipherExample;
  /** External links: source repository, CLI tool, references. */
  links?: CipherLink[];
}

export interface Cipher extends CipherInfo {
  /** Encode cleartext into the format's encoded string. */
  encode(plaintext: string, key?: string): Promise<string>;
  /** Decode an encoded string back to cleartext. */
  decode(encoded: string, key?: string): Promise<string>;
}

/** A badge shown in an explainer's header. */
export interface ExplainerBadge {
  label: string;
  tone?: "default" | "accent" | "muted";
}

/** A row in an explainer's "At a glance" table. */
export interface ExplainerFact {
  term: string;
  value: string;
  /** Render the value in the monospace font (e.g. version numbers). */
  mono?: boolean;
}

/** A "Related" link in an explainer's sidebar (always internal). */
export interface RelatedLink {
  /** Internal path, e.g. "/hash2". */
  href: string;
  label: string;
  note: string;
}

/**
 * A documentation-only page. The shared `ExplainerPage` renders the header,
 * "At a glance" facts, and related links from this metadata; `component`
 * supplies the free-form prose body (styled by `ExplainerPage`).
 */
export interface Explainer {
  /** URL-safe identifier, also the top-level path (`/hash`). */
  id: string;
  /** Display name, e.g. "Nokia hash". */
  name: string;
  /** Vendor, e.g. "Nokia SR OS". */
  vendor: string;
  /** One-line description used in the page header. */
  tagline: string;
  /** Shorter description for the catalogue card; falls back to `tagline`. */
  cardTagline?: string;
  /** Badges shown in the page header. */
  badges: ExplainerBadge[];
  /** "At a glance" fact rows. */
  facts: ExplainerFact[];
  /** "Related" sidebar links. */
  related: RelatedLink[];
  /** The prose body component (content only; layout comes from ExplainerPage). */
  component: Component;
}

/** A converter entry in the catalogue: a `Cipher` plus its computed index. */
export type ConverterEntry = Cipher & { kind: "converter"; index: string };
/** An explainer entry in the catalogue: an `Explainer` plus its computed index. */
export type ExplainerEntry = Explainer & { kind: "explainer"; index: string };
/** Any catalogue entry, discriminated by `kind`. */
export type CatalogueEntry = ConverterEntry | ExplainerEntry;
