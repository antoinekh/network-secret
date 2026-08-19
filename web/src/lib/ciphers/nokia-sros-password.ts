/**
 * Nokia SR OS local user passwords ("$2y$" bcrypt hashes).
 *
 * SR OS stores local user passwords as bcrypt, written in config as
 * "$2y$10$<22-char salt><31-char digest>". It is a one-way hash, like Cisco
 * type 8 and type 9, so `decode` always throws; `verify` recomputes the hash
 * from a candidate password using the salt carried in the given value.
 *
 * "$2a$", "$2b$" and "$2y$" are historical tags for the same underlying
 * algorithm (the tag once marked a Perl/PHP bug in how bcrypt handled
 * certain high-bit passwords; the fix landed under "2b", and "2y" is just
 * PHP's spelling of "the fixed algorithm"). `verify` accepts all three;
 * hashing here always emits "$2y$".
 *
 * Unlike Python's `bcrypt` library - which refuses to generate a "$2y$"
 * salt (`bcrypt.gensalt(10, prefix=b"2y")` raises `ValueError: Supported
 * prefixes are b'2a' or b'2b'`), so `network_secret/nokia_sros_password.py`
 * hashes under "$2b$" and rewrites the prefix afterwards - `bcryptjs`'s
 * internal salt parser (`_hash` in its source) explicitly accepts "a", "b"
 * and "y" as the minor version character and echoes whichever one it was
 * given back into the output. So this module builds a salt string with the
 * "$2y$" prefix directly and lets `bcryptjs` hash under it; the result
 * already carries "$2y$", with no prefix rewrite needed. This was verified
 * against the known-answer vector below (see `web/CLAUDE.md` conventions:
 * verify library behaviour rather than assume it).
 *
 * `bcryptjs`'s asynchronous `hash`/`compare` API is used throughout, not the
 * `*Sync` one: at the accepted cost ceiling a hash takes seconds, and the
 * synchronous call would block the browser's main thread for that whole
 * time, freezing the converter's "Working..." state instead of letting it
 * paint.
 *
 * Mirrors network_secret/nokia_sros_password.py.
 */

import bcrypt from "bcryptjs";
import type { Cipher } from "./types";

export const MAGIC = "$2y$";
// All three markers are the same bcrypt algorithm; verify() accepts any of them.
export const ACCEPTED_PREFIXES = ["$2a$", "$2b$", "$2y$"] as const;
export const DEFAULT_COST = 10;

const ALPHABET =
  "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const SALT_CHARS = 22;
const DIGEST_CHARS = 31;

// bcrypt's cost is an exponent, and it is read from the value being checked, so
// an unbounded cost lets a hostile hash force arbitrarily expensive work: cost
// 31 takes hundreds of hours. Measured on a 2026 laptop: cost 10 is 0.11s, cost
// 14 is 1.9s, cost 16 is 8.5s. 16 accepts any hash a real system produces while
// keeping the worst case bounded. SR OS itself only ever emits cost 10.
export const MIN_COST = 4;
export const MAX_COST = 16;

function splitPrefix(text: string): { tag: string; remainder: string } {
  for (const prefix of ACCEPTED_PREFIXES) {
    if (text.startsWith(prefix)) {
      return { tag: prefix.slice(1, -1), remainder: text.slice(prefix.length) };
    }
  }
  throw new Error(
    `Not a Nokia SR OS bcrypt value: must start with one of ${ACCEPTED_PREFIXES.join(", ")}, got ${JSON.stringify(text)}`,
  );
}

function validateCost(cost: string): void {
  if (!/^\d+$/.test(cost)) {
    throw new Error(`bcrypt cost must be numeric: ${JSON.stringify(cost)}`);
  }
  const value = Number(cost);
  if (value < MIN_COST || value > MAX_COST) {
    throw new Error(`bcrypt cost out of range (${MIN_COST}-${MAX_COST}): ${value}`);
  }
}

function validateChars(rest: string, value: string): void {
  for (const ch of rest) {
    if (!ALPHABET.includes(ch)) {
      throw new Error(
        `Character ${JSON.stringify(ch)} is not in the bcrypt alphabet: ${JSON.stringify(value)}`,
      );
    }
  }
}

/** Parse "$2x$NN$rest" into {tag, cost, rest}; throws on any deviation. */
function parseFields(value: string): { tag: string; cost: string; rest: string } {
  const text = value ? value.trim() : "";
  const { tag, remainder } = splitPrefix(text);
  const sepIndex = remainder.indexOf("$");
  if (sepIndex === -1) {
    throw new Error(`Malformed bcrypt value: ${JSON.stringify(value)}`);
  }
  const cost = remainder.slice(0, sepIndex);
  const rest = remainder.slice(sepIndex + 1);
  validateCost(cost);
  validateChars(rest, value);
  return { tag, cost, rest };
}

/** Parse a full hash "$2x$NN$<22 chars><31 chars>" into its four fields. */
function parseHash(
  value: string,
): { tag: string; cost: string; salt: string; digest: string } {
  const { tag, cost, rest } = parseFields(value);
  if (rest.length !== SALT_CHARS + DIGEST_CHARS) {
    throw new Error(
      `Malformed bcrypt hash: expected a ${SALT_CHARS}-character salt followed by a ` +
        `${DIGEST_CHARS}-character digest, got ${rest.length} characters after the cost: ${JSON.stringify(value)}`,
    );
  }
  return { tag, cost, salt: rest.slice(0, SALT_CHARS), digest: rest.slice(SALT_CHARS) };
}

/** Constant-time string comparison (equal-length strings only). */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export async function encode(plaintext: string): Promise<string> {
  const generated = await bcrypt.genSalt(DEFAULT_COST); // always "$2b$NN$<salt>"
  const ySalt = `${MAGIC}${generated.slice(4)}`;
  return bcrypt.hash(plaintext, ySalt);
}

export async function decode(): Promise<string> {
  throw new Error(
    "Nokia SR OS passwords are bcrypt hashes and cannot be decoded. " +
      "Use Verify to test a password against them.",
  );
}

export async function verify(encoded: string, plaintext: string): Promise<boolean> {
  const { tag, cost, salt } = parseHash(encoded);
  const saltString = `$${tag}$${cost}$${salt}`;
  const recomputed = await bcrypt.hash(plaintext, saltString);
  return timingSafeEqual(encoded.trim(), recomputed);
}

export const nokiaSrosPassword: Cipher = {
  id: "nokia-sros-password",
  name: "Nokia SR OS password",
  vendor: "Nokia SR OS",
  magic: MAGIC,
  tagline:
    "SR OS's bcrypt hash for local user passwords. One-way: you can verify a password against it, not recover one.",
  reversible: false,
  keyed: false,
  oneWay: true,
  status: "available",
  notes: [
    "bcrypt over a 22-character salt, giving a 31-character digest; SR OS always hashes at cost 10.",
    '"$2a$", "$2b$" and "$2y$" are the same underlying algorithm under different historical tags. Verify accepts all three; hashing here always emits "$2y$".',
    "Set as a local user's password in SR OS's system security configuration; the running config carries the $2y$ value verbatim.",
    "One-way: there is nothing to decode, only a candidate password to verify.",
  ],
  example: {
    encoded: "$2y$10$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe",
    plaintext: "lab123",
  },
  links: [
    {
      label: "github.com/antoinekh/network-secret",
      url: "https://github.com/antoinekh/network-secret",
      note: "Python library & CLI.",
    },
  ],
  encode,
  decode,
  verify,
};
