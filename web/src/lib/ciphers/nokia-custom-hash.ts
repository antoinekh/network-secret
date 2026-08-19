/**
 * Nokia SR OS custom-hash.
 *
 * Configured on SR OS via:
 *   admin system security hash-control custom-hash algorithm aes256 key "..."
 *
 * It is deterministic AES in ECB mode with PKCS#7 padding, base64-encoded, and
 * carried in config as "<base64> custom". Because ECB is deterministic, the
 * same plaintext and key produce identical ciphertext on every node sharing the
 * key - which is exactly the point: portable, node-independent secrets.
 *
 * The key is the *literal characters* of the shared-key string (SR OS counts
 * the string length, not a decoded byte length). 16 / 24 / 32 characters select
 * AES-128 / AES-192 / AES-256.
 *
 * Web Crypto (SubtleCrypto) intentionally does not implement ECB, so this uses
 * the small pure-JS `aes-js` library (bundled locally, no CDN).
 */

import aesjs from "aes-js";
import type { Cipher } from "./types";
import { base64ToBytes, bytesToBase64 } from "../base64";

const SUFFIX = "custom";
const BLOCK = 16;

function keyBytes(key: string): Uint8Array {
  const bytes = new TextEncoder().encode(key);
  if (bytes.length !== 16 && bytes.length !== 24 && bytes.length !== 32) {
    throw new Error(
      `Key must be 16, 24, or 32 characters (AES-128 / AES-192 / AES-256); got ${bytes.length}`,
    );
  }
  return bytes;
}

function pkcs7Pad(data: Uint8Array): Uint8Array {
  const padLen = BLOCK - (data.length % BLOCK);
  const out = new Uint8Array(data.length + padLen);
  out.set(data);
  out.fill(padLen, data.length);
  return out;
}

function pkcs7Unpad(data: Uint8Array): Uint8Array {
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > BLOCK || padLen > data.length) {
    throw new Error("Invalid PKCS#7 padding");
  }
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) {
      throw new Error("Invalid PKCS#7 padding");
    }
  }
  return data.slice(0, data.length - padLen);
}

export async function encode(plaintext: string, key?: string): Promise<string> {
  if (!key) {
    throw new Error("A shared AES key is required");
  }
  const ecb = new aesjs.ModeOfOperation.ecb(keyBytes(key));
  const ciphertext = ecb.encrypt(pkcs7Pad(new TextEncoder().encode(plaintext)));
  return `${bytesToBase64(ciphertext, true)} ${SUFFIX}`;
}

export async function decode(encoded: string, key?: string): Promise<string> {
  if (!key) {
    throw new Error("A shared AES key is required");
  }
  const b64 = encoded
    .trim()
    .replace(/\s+custom$/i, "")
    .trim();
  const raw = base64ToBytes(b64);
  if (raw.length === 0 || raw.length % BLOCK !== 0) {
    throw new Error("Invalid ciphertext: length is not a multiple of the AES block size");
  }
  const ecb = new aesjs.ModeOfOperation.ecb(keyBytes(key));
  try {
    const plain = pkcs7Unpad(ecb.decrypt(raw));
    return new TextDecoder("utf-8", { fatal: true }).decode(plain);
  } catch {
    throw new Error("Decryption failed: wrong key, or not a valid custom-hash value");
  }
}

export const nokiaCustomHash: Cipher = {
  id: "nokia-custom-hash",
  name: "Nokia custom-hash",
  vendor: "Nokia SR OS",
  magic: "",
  tagline: "Deterministic AES-ECB hash-control secrets for SR OS, portable across nodes that share the key.",
  reversible: false,
  keyed: true,
  keyLabel: "Shared AES key",
  status: "available",
  notes: [
    "SR OS hash-control custom-hash: AES in ECB mode with PKCS#7 padding, base64 output, written as '<base64> custom'.",
    "The key is the literal characters of the shared key: 16, 24, or 32 characters select AES-128 / AES-192 / AES-256.",
    "ECB is deterministic, so the same plaintext and key yield identical ciphertext on every node, which is the whole point of custom-hash.",
    'Loaded with: admin system security hash-control custom-hash algorithm aes256 key "…".',
  ],
  example: {
    encoded: "Xfs39BMeblOtlorgwTChxQ== custom",
    plaintext: "L@bS3cr3t!",
    key: "a3f8d9e112c04b7af1c3e8b92d057a4e",
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
};
