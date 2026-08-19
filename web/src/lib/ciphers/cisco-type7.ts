/**
 * Cisco IOS / IOS-XE type 7 passwords.
 *
 * Legacy reversible obfuscation, written as `password 7 060506324F41`. The
 * key is fixed and present in every IOS image, so this protects nothing. It
 * is here because existing configurations are full of it.
 *
 * Mirrors network_secret/cisco_type7.py.
 */

import type { Cipher } from "./types";

const KEY = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87";
const MAX_ENCRYPT_SEED = 15;

function xor(data: Uint8Array, seed: number): Uint8Array {
  return data.map((b, i) => b ^ KEY.charCodeAt((seed + i) % KEY.length));
}

async function encode(plaintext: string): Promise<string> {
  const seed = Math.floor(Math.random() * (MAX_ENCRYPT_SEED + 1));
  const data = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) {
    const code = plaintext.charCodeAt(i);
    if (code > 255) {
      throw new Error(
        "Only single-byte (Latin-1) characters can be type 7 encoded",
      );
    }
    data[i] = code;
  }
  const body = Array.from(xor(data, seed), (b) =>
    b.toString(16).toUpperCase().padStart(2, "0"),
  ).join("");
  return String(seed).padStart(2, "0") + body;
}

async function decode(encoded: string): Promise<string> {
  const text = encoded.trim();
  if (text.length < 2) {
    throw new Error("Not a Cisco type 7 value: too short to hold a seed");
  }
  const seedText = text.slice(0, 2);
  if (!/^[0-9]{2}$/.test(seedText)) {
    throw new Error(
      `Invalid type 7 seed '${seedText}': expected two decimal digits`,
    );
  }
  const seed = Number(seedText);
  if (seed >= KEY.length) {
    throw new Error(`Type 7 seed ${seed} out of range (0-${KEY.length - 1})`);
  }
  const body = text.slice(2);
  if (body.length % 2) {
    throw new Error("Malformed type 7 value: the hex body has an odd length");
  }
  if (!/^[0-9a-fA-F]*$/.test(body)) {
    throw new Error(`Invalid hex in type 7 value: '${body}'`);
  }
  const raw = new Uint8Array(body.length / 2);
  for (let i = 0; i < raw.length; i++) {
    raw[i] = parseInt(body.slice(i * 2, i * 2 + 2), 16);
  }
  return Array.from(xor(raw, seed), (b) => String.fromCharCode(b)).join("");
}

export const ciscoType7: Cipher = {
  id: "cisco-type7",
  name: "Cisco type 7",
  vendor: "Cisco IOS",
  magic: "",
  tagline:
    "IOS's legacy password obfuscation. The key ships inside every image, so anyone can read it. Still everywhere in existing configs.",
  reversible: true,
  keyed: false,
  status: "available",
  notes: [
    "A two-digit decimal seed, then hex pairs. Each byte is XORed with a fixed 53-character key compiled into IOS.",
    "This is obfuscation, not encryption. Treat any type 7 value you find as cleartext.",
    "Written as: password 7 060506324F41, or service password-encryption for the whole config.",
    "IOS emits a seed of 0 to 15, so the same secret encodes 16 different ways. All of them decode identically.",
  ],
  example: { encoded: "060506324F41", plaintext: "cisco" },
  encode,
  decode,
};
