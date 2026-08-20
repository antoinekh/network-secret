/**
 * JUNOS local-user "encrypted-password" hashes ("$5$" and "$6$" crypt).
 *
 * JUNOS stores local user passwords as standard Unix SHA-crypt, written in
 * config as:
 *
 *   encrypted-password "$5$itHMToxg$IAeDKDuWsSCoL2W7fognCW8cyNj4YE9ZhDvCoWFC5y/"; ## SECRET-DATA
 *
 * Two variants are supported, both Ulrich Drepper's SHA-crypt algorithm keyed
 * by a different hash function (see `../sha-crypt.ts` for the shared
 * implementation):
 *
 *   $5$  sha256-crypt
 *   $6$  sha512-crypt
 *
 * "$1$" (md5crypt) is a distinct, older algorithm and is out of scope: it is
 * rejected with an error naming it, rather than falling through to a generic
 * parse failure.
 *
 * Like Cisco type 8/9 and the Nokia SR OS password format, this is a one-way
 * hash: `decode` always throws, and `verify` recomputes the hash from a
 * candidate password using the salt (and rounds) carried in the given value.
 *
 * "$5$"/"$6$" embed an optional "rounds=N$" field in the salt, which the
 * algorithm reads from whatever untrusted value is being verified. Drepper's
 * spec permits N up to 999,999,999; `openssl passwd` itself hangs for a very
 * long time computing that. MIN_ROUNDS/MAX_ROUNDS bound what this module
 * accepts, checked *before any hashing happens*, mirroring
 * `network_secret/juniper_encrypted_password.py` on this branch exactly
 * (same bounds, same precedent as Nokia SR OS bcrypt's cost bound in
 * `nokia-sros-password.ts`).
 *
 * Mirrors network_secret/juniper_encrypted_password.py.
 */

import {
  ALPHABET,
  encodeDigest,
  generateSalt,
  hashPassword,
  type HashName,
} from "../sha-crypt";
import type { Cipher } from "./types";

export const MAGIC_SHA256 = "$5$";
export const MAGIC_SHA512 = "$6$";
const MAGIC_MD5 = "$1$"; // explicitly unsupported; named in its own error below

export const DEFAULT_ROUNDS = 5000;
// Drepper's spec allows 1000-999999999. The upper end is read from whatever
// value is being verified, so it must be bounded well below the spec's own
// maximum or a pasted hash can force minutes of hashing in the browser tab.
// Matches network_secret/juniper_encrypted_password.py's MIN_ROUNDS/MAX_ROUNDS
// exactly.
export const MIN_ROUNDS = 1000;
export const MAX_ROUNDS = 100_000;

export const SECRET_DATA_MARKER = "## SECRET-DATA";

const ROUNDS_PREFIX = "rounds=";
const MAX_SALT_LEN = 16;
const HASH_NAME: Record<string, HashName> = {
  [MAGIC_SHA256]: "SHA-256",
  [MAGIC_SHA512]: "SHA-512",
};
// Encoded-hash length is fixed per variant: 32 bytes -> 43 chars for sha256,
// 64 bytes -> 86 chars for sha512 (see sha-crypt.ts's encodeDigest).
const HASH_FIELD_LEN: Record<string, number> = {
  [MAGIC_SHA256]: 43,
  [MAGIC_SHA512]: 86,
};

/**
 * Strip config decoration a pasted line may carry around the value.
 *
 * Repeatedly strips surrounding whitespace, a trailing SECRET_DATA_MARKER, a
 * trailing ';', and one layer of matching surrounding quotes, in any order
 * and any combination, until none apply. This lets a caller paste the
 * quoted value straight out of a config line, decoration and all:
 *
 *   "$5$salt$hash"; ## SECRET-DATA
 *
 * It does NOT strip a leading "encrypted-password " keyword: nothing here
 * looks for or removes it, so the full config line including that keyword
 * fails to parse. Start from the opening quote (or from "$5$"/"$6$" itself
 * if there is no quoting).
 */
function stripDecoration(value: string): string {
  let text = value;
  let changed = true;
  while (changed) {
    changed = false;
    const trimmed = text.trim();
    if (trimmed !== text) {
      text = trimmed;
      changed = true;
      continue;
    }
    if (text.endsWith(SECRET_DATA_MARKER)) {
      text = text.slice(0, -SECRET_DATA_MARKER.length);
      changed = true;
      continue;
    }
    if (text.endsWith(";")) {
      text = text.slice(0, -1);
      changed = true;
      continue;
    }
    if (
      text.length >= 2 &&
      text[0] === text[text.length - 1] &&
      (text[0] === "'" || text[0] === '"')
    ) {
      text = text.slice(1, -1);
      changed = true;
      continue;
    }
  }
  return text;
}

/** Split a leading "$5$"/"$6$" from `text`; throw otherwise. */
function parsePrefix(text: string): { magic: string; rest: string } {
  if (text.startsWith(MAGIC_MD5)) {
    throw new Error(
      "$1$ (md5crypt) is not a supported variant: only $5$ (sha256-crypt) " +
        "and $6$ (sha512-crypt) are accepted.",
    );
  }
  for (const magic of [MAGIC_SHA256, MAGIC_SHA512]) {
    if (text.startsWith(magic)) {
      return { magic, rest: text.slice(magic.length) };
    }
  }
  throw new Error(
    `Not a JUNOS encrypted-password value: must start with '${MAGIC_SHA256}' ` +
      `or '${MAGIC_SHA512}', got '${text}'`,
  );
}

function parseRoundsNumber(text: string): number {
  // Require plain ASCII digits only (mirrors Python's `text.isascii() and
  // text.isdigit()`, which rejects both empty strings and non-ASCII digits).
  if (!/^[0-9]+$/.test(text)) {
    throw new Error(`Invalid rounds value: '${text}'`);
  }
  const value = Number(text);
  if (value < MIN_ROUNDS || value > MAX_ROUNDS) {
    throw new Error(`rounds out of range (${MIN_ROUNDS}-${MAX_ROUNDS}): ${value}`);
  }
  return value;
}

/**
 * Split an optional leading "rounds=N$" from `text`.
 *
 * Returns (rounds, roundsRaw, rest). `roundsRaw` is the exact digit
 * substring as given (e.g. "007000"), or null if no "rounds=" field was
 * present at all. It is kept verbatim, leading zeros and all, rather than
 * reduced to `rounds` and reformatted with `String()`: a value written by
 * another tool may carry non-canonical digits (openssl accepts and computes
 * "rounds=007000" identically to "rounds=7000"), and if `format` re-emitted
 * that field from the number it would silently canonicalise it, making
 * `recomputed` diverge from `given` in the rounds field alone - so a correct
 * password would compare as a mismatch. Mirrors Python's `_split_rounds` on
 * this branch. The out-of-range check happens here, before any hashing is
 * ever attempted.
 */
function splitRounds(
  text: string,
): { rounds: number; roundsRaw: string | null; rest: string } {
  if (text.startsWith(ROUNDS_PREFIX)) {
    const afterPrefix = text.slice(ROUNDS_PREFIX.length);
    const sepIndex = afterPrefix.indexOf("$");
    if (sepIndex === -1) {
      throw new Error(`Malformed rounds field: '${text}'`);
    }
    const numPart = afterPrefix.slice(0, sepIndex);
    const rest = afterPrefix.slice(sepIndex + 1);
    return { rounds: parseRoundsNumber(numPart), roundsRaw: numPart, rest };
  }
  return { rounds: DEFAULT_ROUNDS, roundsRaw: null, rest: text };
}

function validateSalt(salt: string): void {
  if (!salt) throw new Error("Empty salt");
  if (salt.length > MAX_SALT_LEN) {
    throw new Error(`Salt too long (max ${MAX_SALT_LEN} characters): '${salt}'`);
  }
  for (const ch of salt) {
    if (!ALPHABET.includes(ch)) {
      throw new Error(`Character '${ch}' is not in the crypt alphabet: salt '${salt}'`);
    }
  }
}

function validateHashField(hashField: string, magic: string): void {
  if (!hashField) throw new Error("Malformed value: empty hash field");
  for (const ch of hashField) {
    if (!ALPHABET.includes(ch)) {
      throw new Error(
        `Character '${ch}' is not in the crypt alphabet: hash '${hashField}'`,
      );
    }
  }
  const expected = HASH_FIELD_LEN[magic];
  if (hashField.length !== expected) {
    throw new Error(
      `Malformed hash field: expected ${expected} characters for ${magic}, ` +
        `got ${hashField.length}`,
    );
  }
}

/**
 * Parse an `encode`-style salt argument into its fields.
 *
 * Accepts a bare salt ("abcdefgh"), a "rounds=N$salt" form, or either of
 * those prefixed with "$5$"/"$6$" to select the variant. With no "$5$"/
 * "$6$" prefix, the variant defaults to MAGIC_SHA512. This mirrors Python's
 * `_parse_salt_arg` / `encrypt(plaintext, salt=...)`; the web `Cipher`
 * interface's `encode(plaintext)` takes no salt argument (it always draws a
 * fresh random one), so `encryptWithSalt` is exported separately, mainly to
 * let tests exercise both variants and the rounds= form the same way the
 * Python suite does.
 */
function parseSaltArg(
  saltArg: string,
): { magic: string; rounds: number; roundsRaw: string | null; salt: string } {
  const text = saltArg.trim();
  let magic: string;
  let rest: string;
  if (text.startsWith("$")) {
    ({ magic, rest } = parsePrefix(text));
  } else {
    magic = MAGIC_SHA512;
    rest = text;
  }
  const { rounds, roundsRaw, rest: salt } = splitRounds(rest);
  validateSalt(salt);
  return { magic, rounds, roundsRaw, salt };
}

/** Parse a full "$5$[rounds=N$]salt$hash" value, decoration and all. */
function parseValue(
  value: string,
): { magic: string; rounds: number; roundsRaw: string | null; salt: string; hashField: string } {
  const text = stripDecoration(value);
  const { magic, rest } = parsePrefix(text);
  const { rounds, roundsRaw, rest: rest2 } = splitRounds(rest);
  const sepIndex = rest2.indexOf("$");
  if (sepIndex === -1) {
    throw new Error(`Malformed value: missing hash field: '${value}'`);
  }
  const salt = rest2.slice(0, sepIndex);
  const hashField = rest2.slice(sepIndex + 1);
  validateSalt(salt);
  validateHashField(hashField, magic);
  return { magic, rounds, roundsRaw, salt, hashField };
}

async function compute(
  magic: string,
  password: string,
  salt: string,
  rounds: number,
): Promise<string> {
  const hashName = HASH_NAME[magic];
  const digest = await hashPassword(password, salt, rounds, hashName);
  return encodeDigest(digest, hashName);
}

/**
 * Assemble "$N$[rounds=<roundsDisplay>$]salt$hash".
 *
 * `roundsDisplay` is the exact digit string to write, or null to omit the
 * field entirely. The two callers deliberately pass different things here:
 * `verify` passes the raw digit substring parsed from the given value
 * (preserving e.g. non-canonical leading zeros, so a correct password's
 * recomputation matches what the user pasted - see `splitRounds`), while
 * `encryptWithSalt` passes `String(rounds)` (canonical digits only, since it
 * is minting a brand new value and must never inherit another tool's
 * formatting quirks - matching `openssl passwd`, which likewise accepts
 * non-canonical rounds on input but always normalises its own output).
 * Mirrors Python's `_format`/`encrypt`/`check` split on this branch.
 */
function format(
  magic: string,
  roundsDisplay: string | null,
  salt: string,
  encoded: string,
): string {
  const roundsField = roundsDisplay !== null ? `${ROUNDS_PREFIX}${roundsDisplay}$` : "";
  return `${magic}${roundsField}${salt}$${encoded}`;
}

/** Compare two strings without short-circuiting on the first difference. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Hash `plaintext` into a JUNOS encrypted-password value, mirroring Python's
 * `encrypt(plaintext, salt=...)` called with no `salt` argument: emits
 * "$6$" (sha512-crypt) since that is what current JUNOS writes, at
 * DEFAULT_ROUNDS, with a fresh random 16-character salt. Non-deterministic:
 * the same password produces a different hash each call.
 */
export async function encode(plaintext: string): Promise<string> {
  const salt = generateSalt();
  const encoded = await compute(MAGIC_SHA512, plaintext, salt, DEFAULT_ROUNDS);
  return format(MAGIC_SHA512, null, salt, encoded);
}

/**
 * Mirrors Python's `encrypt(plaintext, salt=...)` with an explicit `salt`
 * argument. See `parseSaltArg` for the accepted forms. Exported (but not
 * part of the `Cipher` interface) so tests can exercise the "$5$" variant
 * and the "rounds=" form directly, the way the Python suite does.
 *
 * Canonicalises the rounds field: a "rounds=007000$..." argument produces
 * "rounds=7000$..." in the output. This is a freshly minted value, so it
 * must not inherit another tool's non-canonical formatting - unlike
 * `verify`, which preserves the raw digits it was given because it is
 * echoing back what the user pasted. See `format`'s docstring for the full
 * rationale (mirrors Python's `encrypt`/`check` split exactly).
 */
export async function encryptWithSalt(plaintext: string, saltArg: string): Promise<string> {
  const { magic, rounds, roundsRaw, salt } = parseSaltArg(saltArg);
  const roundsDisplay = roundsRaw !== null ? String(rounds) : null;
  const encoded = await compute(magic, plaintext, salt, rounds);
  return format(magic, roundsDisplay, salt, encoded);
}

/** Always throws: encrypted-password is a one-way hash, not a cipher. */
export async function decode(): Promise<string> {
  throw new Error(
    "JUNOS encrypted-password values are a one-way SHA-crypt hash and " +
      "cannot be decrypted. Use Verify to test a password against it.",
  );
}

/**
 * Recompute `encoded` from the password `plaintext` and compare.
 *
 * The variant, rounds, and salt are taken from `encoded` (after stripping
 * config decoration - see SECRET_DATA_MARKER), so an equal password
 * reproduces the whole value.
 */
export async function verify(encoded: string, plaintext: string): Promise<boolean> {
  const { magic, rounds, roundsRaw, salt } = parseValue(encoded);
  const recomputedHash = await compute(magic, plaintext, salt, rounds);
  const recomputed = format(magic, roundsRaw, salt, recomputedHash);
  const given = stripDecoration(encoded);
  return timingSafeEqual(given, recomputed);
}

export const juniperEncryptedPassword: Cipher = {
  id: "juniper-encrypted-password",
  name: "JUNOS encrypted-password",
  vendor: "Juniper/HPE",
  magic: "$5$/$6$",
  tagline:
    "JUNOS local-user password hashes: Unix SHA-crypt ($5$ sha256-crypt, $6$ sha512-crypt). One-way: you can verify a password against it, not recover one.",
  reversible: false,
  keyed: false,
  oneWay: true,
  status: "available",
  notes: [
    "Drepper's SHA-crypt: the same digest-chain algorithm keyed by sha256 ($5$) or sha512 ($6$), run for rounds (5000 by default) over the password and a salt.",
    "The digest is written in SHA-crypt's own base64 variant: little-endian 6-bit groups, in a shuffled byte order that differs from both standard base64 and Cisco's variant.",
    "An optional 'rounds=N$' field in the salt selects a custom round count between 1000 and 100000 here; JUNOS itself always writes the 5000 default.",
    "$1$ (md5crypt) is a distinct, older algorithm and is out of scope: it is rejected by name rather than silently mishandled.",
    "Written as: encrypted-password \"$5$salt$hash\"; ## SECRET-DATA.",
  ],
  example: {
    encoded: "$5$itHMToxg$IAeDKDuWsSCoL2W7fognCW8cyNj4YE9ZhDvCoWFC5y/",
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
