/**
 * Framing shared by the Cisco IOS one-way password hashes.
 *
 * Type 8 and type 9 use the same `$<type>$<salt>$<hash>` framing, the same
 * salt rules and the same output encoding. They differ only in the key
 * derivation function.
 *
 * Mirrors network_secret/_cisco_hash.py.
 */

import { CISCO_ALPHABET, ciscoBase64 } from "./cisco-b64";

export const DIGEST_LEN = 32;
export const SALT_LEN = 14;

/** Takes (password, salt) as bytes and returns DIGEST_LEN bytes. */
export type Kdf = (password: Uint8Array, salt: Uint8Array) => Promise<Uint8Array>;

export function generateSalt(): string {
  const raw = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  return Array.from(raw, (b) => CISCO_ALPHABET[b & 0x3f]).join("");
}

/**
 * Return `salt` unchanged if IOS would accept it, else throw.
 *
 * IOS accepts printable ASCII other than space and '$'. Length is not
 * checked: IOS generates 14 characters but copies a given salt verbatim.
 */
export function validateSalt(salt: string): string {
  if (!salt) throw new Error("Empty salt");
  for (const ch of salt) {
    const code = ch.codePointAt(0)!;
    if (ch === "$" || code <= 0x20 || code > 0x7e) {
      throw new Error(`Invalid character '${ch}' in salt '${salt}'`);
    }
  }
  return salt;
}

export function parseHash(
  value: string,
  typeNumber: number,
): { salt: string; encoded: string } {
  const magic = `$${typeNumber}$`;
  const text = value.trim();
  if (!text.startsWith(magic)) {
    throw new Error(
      `Not a Cisco type ${typeNumber} hash: must start with ${magic}`,
    );
  }
  // A leading '$' yields an empty first element.
  const parts = text.split("$");
  if (parts.length !== 4) {
    throw new Error(
      `Malformed type ${typeNumber} hash: expected $<type>$<salt>$<hash>`,
    );
  }
  const [, , salt, encoded] = parts;
  validateSalt(salt);
  if (!encoded) {
    throw new Error(`Malformed type ${typeNumber} hash: empty hash field`);
  }
  for (const ch of encoded) {
    if (!CISCO_ALPHABET.includes(ch)) {
      throw new Error(`Character '${ch}' is not in the Cisco base64 alphabet`);
    }
  }
  return { salt, encoded };
}

export async function hashPassword(
  password: string,
  kdf: Kdf,
  typeNumber: number,
  salt?: string,
): Promise<string> {
  const chosen = salt === undefined ? generateSalt() : validateSalt(salt);
  const digest = await kdf(
    new TextEncoder().encode(password),
    new TextEncoder().encode(chosen),
  );
  return `$${typeNumber}$${chosen}$${ciscoBase64(digest)}`;
}

export async function verifyHash(
  value: string,
  password: string,
  kdf: Kdf,
  typeNumber: number,
): Promise<boolean> {
  const { salt } = parseHash(value, typeNumber);
  const recomputed = await hashPassword(password, kdf, typeNumber, salt);
  const given = value.trim();
  if (given.length !== recomputed.length) return false;
  let diff = 0;
  for (let i = 0; i < given.length; i++) {
    diff |= given.charCodeAt(i) ^ recomputed.charCodeAt(i);
  }
  return diff === 0;
}

export function oneWayError(typeNumber: number): Error {
  return new Error(
    `Cisco type ${typeNumber} is a one-way hash and cannot be decoded. ` +
      "Use Verify to test a password against it.",
  );
}
