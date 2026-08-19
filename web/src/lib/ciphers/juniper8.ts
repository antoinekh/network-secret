/**
 * Juniper/HPE $8$ (type 8) authenticated encryption.
 *
 * Unlike $9$, $8$ is genuine authenticated encryption keyed by the device
 * master password. Reverse-engineered and verified against a real JUNOS 23.2
 * device:
 *
 *   $8$<crypt-algo>$<hash-algo>$<iterations>$<salt>$<iv>$<tag>$<ciphertext>
 *
 * - encoding : standard base64, no padding, for every binary field.
 * - key      : PBKDF2-HMAC-SHA256(master, salt, iterations) -> 32-byte AES key.
 * - cipher   : AES-256-GCM, no additional authenticated data.
 * - nonce    : the iv field is 16 bytes but only the first 12 are the GCM
 *              nonce; the trailing 4 bytes are unused.
 *
 * All crypto runs in the browser via the Web Crypto API (SubtleCrypto).
 */

import type { Cipher } from "./types";
import { base64ToBytes, bytesToBase64 } from "../base64";

const MAGIC = "$8$";
const CRYPT_ALGO = "aes256-gcm";
const HASH_ALGO = "hmac-sha2-256";
const DEFAULT_ITERATIONS = 100;
const SALT_LEN = 8;
const IV_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;

function getCrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error("Web Crypto API is not available in this environment");
  }
  return c;
}

/**
 * Cast a Uint8Array to BufferSource. TypeScript's DOM lib (>=5.7) narrows
 * BufferSource to ArrayBuffer-backed views, which our plain Uint8Arrays
 * satisfy at runtime but not in the type system.
 */
function buf(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

async function deriveKey(
  master: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const c = getCrypto();
  const base = await c.subtle.importKey(
    "raw",
    buf(new TextEncoder().encode(master)),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return c.subtle.deriveKey(
    { name: "PBKDF2", salt: buf(salt), iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encode(plaintext: string, master?: string): Promise<string> {
  if (!master) {
    throw new Error("A master password is required to encrypt a $8$ value");
  }
  const c = getCrypto();
  const salt = c.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = c.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(master, salt, DEFAULT_ITERATIONS);
  const nonce = iv.slice(0, NONCE_LEN);
  const sealed = new Uint8Array(
    await c.subtle.encrypt(
      { name: "AES-GCM", iv: buf(nonce), tagLength: 128 },
      key,
      buf(new TextEncoder().encode(plaintext)),
    ),
  );
  const ciphertext = sealed.slice(0, sealed.length - TAG_LEN);
  const tag = sealed.slice(sealed.length - TAG_LEN);
  return (
    MAGIC +
    [
      CRYPT_ALGO,
      HASH_ALGO,
      String(DEFAULT_ITERATIONS),
      bytesToBase64(salt),
      bytesToBase64(iv),
      bytesToBase64(tag),
      bytesToBase64(ciphertext),
    ].join("$")
  );
}

export async function decode(encoded: string, master?: string): Promise<string> {
  if (!master) {
    throw new Error("A master password is required to decrypt a $8$ value");
  }
  encoded = encoded.trim();
  if (!encoded.startsWith(MAGIC)) {
    throw new Error("Not a Juniper/HPE $8$ string: must start with $8$");
  }
  const parts = encoded.split("$");
  if (parts.length !== 9) {
    throw new Error("Malformed $8$ value: expected 7 fields after the prefix");
  }
  const [, , cryptAlgo, hashAlgo, iters, saltB, ivB, tagB, ctB] = parts;
  if (cryptAlgo !== CRYPT_ALGO) {
    throw new Error(`Unsupported crypt-algo '${cryptAlgo}': only ${CRYPT_ALGO}`);
  }
  if (hashAlgo !== HASH_ALGO) {
    throw new Error(`Unsupported hash-algo '${hashAlgo}': only ${HASH_ALGO}`);
  }
  if (!/^\d+$/.test(iters)) {
    throw new Error(`Invalid iteration count: '${iters}'`);
  }
  const salt = base64ToBytes(saltB);
  const iv = base64ToBytes(ivB);
  const tag = base64ToBytes(tagB);
  const ciphertext = base64ToBytes(ctB);

  const key = await deriveKey(master, salt, parseInt(iters, 10));
  const data = new Uint8Array(ciphertext.length + tag.length);
  data.set(ciphertext);
  data.set(tag, ciphertext.length);
  const nonce = iv.slice(0, NONCE_LEN);
  try {
    const c = getCrypto();
    const plaintext = await c.subtle.decrypt(
      { name: "AES-GCM", iv: buf(nonce), tagLength: 128 },
      key,
      buf(data),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    throw new Error(
      "Authentication failed: wrong master password, or the value was not produced by this scheme",
    );
  }
}

export const juniper8: Cipher = {
  id: "juniper8",
  name: "Juniper/HPE $8$",
  vendor: "Juniper/HPE",
  magic: "$8$",
  tagline:
    "Juniper/HPE type 8 ($8$): master-password-keyed AES-256-GCM encryption for JUNOS secrets.",
  reversible: false,
  keyed: true,
  keyLabel: "Master password",
  status: "available",
  notes: [
    "$8$ is real authenticated encryption: PBKDF2-HMAC-SHA256 derives an AES-256-GCM key from the master password.",
    "Decryption requires the same master password set on the device (set system master-password).",
    "The 16-byte iv field is stored in full, but only its first 12 bytes are used as the GCM nonce.",
    "A wrong master password fails the GCM authentication tag, so decoding reports an error instead of garbage.",
  ],
  example: {
    encoded:
      "$8$aes256-gcm$hmac-sha2-256$100$p8XEvHtxRNE$d/hqRmh5etkBzo7WSdtvjg$7w1eMTYXkz4RdzMF9CAkJQ$qVLunbFwBWwyxln2Vg",
    plaintext: "LabBgpSecret1",
    key: "a3f8d9e112c04b7af1c3e8b92d057a4e",
  },
  links: [
    {
      label: "github.com/antoinekh/network-secret",
      url: "https://github.com/antoinekh/network-secret",
      note: "Python library & CLI, plus how the format was reverse-engineered.",
    },
  ],
  encode,
  decode,
};
