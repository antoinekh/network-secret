/**
 * Cisco IOS / IOS-XE type 9 password hashes.
 *
 * scrypt with N=16384, r=1, p=1 over the salt's raw ASCII bytes. It replaced
 * type 8 to raise the memory cost of an offline attack, which is also why it
 * takes a visible moment in the browser.
 *
 * Mirrors network_secret/cisco_type9.py.
 */

import { scrypt } from "scrypt-js";
import {
  DIGEST_LEN,
  hashPassword,
  oneWayError,
  verifyHash,
  type Kdf,
} from "../cisco-hash";
import type { Cipher } from "./types";

const TYPE_NUMBER = 9;
const N = 16384;
const R = 1;
const P = 1;

const kdf: Kdf = async (password, salt) =>
  Uint8Array.from(await scrypt(password, salt, N, R, P, DIGEST_LEN));

export const ciscoType9: Cipher = {
  id: "cisco-type9",
  name: "Cisco type 9",
  vendor: "Cisco IOS",
  magic: "$9$",
  tagline:
    "IOS's scrypt password hash, the successor to type 8. One-way, and deliberately memory-hard, so it takes a moment.",
  reversible: false,
  keyed: false,
  oneWay: true,
  status: "available",
  notes: [
    "scrypt with N=16384, r=1 and p=1 over a 14-character salt, giving a 32-byte digest.",
    "Memory-hard by design: it needs about 2 MB per guess, which is what makes an offline attack expensive.",
    "Careful: a Cisco $9$ and a Juniper/HPE $9$ share a prefix and nothing else. The Juniper/HPE one is a keyless substitution cipher anyone can reverse; this one is a hash.",
    "Written as: username admin secret 9 $9$salt$hash.",
  ],
  example: {
    encoded: "$9$ihSswXDbk0kaVK$o.uyR2nMrWtjMkrQwBXUR5lVuVt/KzG23rmYvshODXI",
    plaintext: "cisco123",
  },
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
