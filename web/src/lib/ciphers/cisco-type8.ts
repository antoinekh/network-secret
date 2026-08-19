/**
 * Cisco IOS / IOS-XE type 8 password hashes.
 *
 * PBKDF2-HMAC-SHA256, 20000 iterations, over the salt's raw ASCII bytes.
 * One-way: decode always throws, and verify recomputes with the salt taken
 * from the given hash.
 *
 * Mirrors network_secret/cisco_type8.py.
 */

import {
  DIGEST_LEN,
  hashPassword,
  oneWayError,
  verifyHash,
  type Kdf,
} from "../cisco-hash";
import type { Cipher } from "./types";

const TYPE_NUMBER = 8;
const ITERATIONS = 20000;

/**
 * Cast a Uint8Array to BufferSource. TypeScript's DOM lib (>=5.7) narrows
 * BufferSource to ArrayBuffer-backed views, which our plain Uint8Arrays
 * satisfy at runtime but not in the type system.
 */
function buf(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

const kdf: Kdf = async (password, salt) => {
  const key = await crypto.subtle.importKey(
    "raw",
    buf(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: buf(salt), iterations: ITERATIONS, hash: "SHA-256" },
    key,
    DIGEST_LEN * 8,
  );
  return new Uint8Array(bits);
};

export const ciscoType8: Cipher = {
  id: "cisco-type8",
  name: "Cisco type 8",
  vendor: "Cisco IOS",
  magic: "$8$",
  tagline:
    "IOS's PBKDF2-SHA256 password hash for local users and enable secrets. One-way: you can verify a password against it, not recover one.",
  reversible: false,
  keyed: false,
  oneWay: true,
  status: "available",
  notes: [
    "PBKDF2-HMAC-SHA256 with 20000 iterations over a 14-character salt, giving a 32-byte digest.",
    "The digest is written in Cisco's own base64 alphabet, './0-9A-Za-z', with no padding, so a hash is always 43 characters.",
    "Careful: a Cisco $8$ and a Juniper/HPE $8$ share a prefix and nothing else. The Juniper/HPE one is reversible AES-256-GCM; this one is a hash.",
    "Written as: username admin secret 8 $8$salt$hash.",
  ],
  example: {
    encoded: "$8$J5J/1K3e8gk974$HRezVpnMZOhOU2uxFTv.79S1U1PpMScizwXS3Z1Dx1s",
    plaintext: "cisco123",
  },
  links: [
    {
      label: "github.com/antoinekh/network-secret",
      url: "https://github.com/antoinekh/network-secret",
      note: "Python library & CLI.",
    },
    {
      label: "github.com/CiscoDevNet/Type-6-Password-Encode",
      url: "https://github.com/CiscoDevNet/Type-6-Password-Encode",
      note: "Cisco's own reference implementation and test vectors.",
    },
  ],
  async encode(plaintext: string): Promise<string> {
    return hashPassword(plaintext, kdf, TYPE_NUMBER);
  },
  async decode(): Promise<string> {
    throw oneWayError(TYPE_NUMBER);
  },
  async verify(encoded: string, plaintext: string): Promise<boolean> {
    return verifyHash(encoded, plaintext, kdf, TYPE_NUMBER);
  },
};
