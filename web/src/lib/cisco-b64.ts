/**
 * Cisco's base64 variant, used by type 8 and type 9 hashes.
 *
 * Standard base64 bit order over Cisco's own 64-character alphabet, with no
 * padding. A 32-byte digest becomes 43 characters.
 */

import { bytesToBase64 } from "./base64";

export const CISCO_ALPHABET =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const STANDARD_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function ciscoBase64(digest: Uint8Array): string {
  return [...bytesToBase64(digest)]
    .map((c) => CISCO_ALPHABET[STANDARD_ALPHABET.indexOf(c)])
    .join("");
}
