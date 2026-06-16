/**
 * The contract every cipher module implements.
 *
 * Adding a new format (e.g. Nokia SR OS custom-hash) means writing one module
 * that exports a `Cipher` and registering it in `registry.ts`. The home page
 * card and the per-format page are generated from this metadata, so a new
 * cipher appears across the whole site automatically.
 */

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
  /** URL-safe identifier, e.g. "juniper9". */
  id: string;
  /** Two-digit catalogue index shown in the editorial layout, e.g. "01". */
  index: string;
  /** Display name, e.g. "Juniper $9$". */
  name: string;
  /** Vendor, e.g. "Juniper". */
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
