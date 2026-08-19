/**
 * Cisco IOS / IOS-XE type 6 encrypted secrets.
 *
 * Reversible authenticated encryption, keyed by the master key set with
 * `key config-key password-encrypt`.
 *
 *   md5        = MD5(master key)                       -> AES-128 key
 *   ke         = AES-128-ECB(md5, salt || 00*7 || 01)
 *   ka         = AES-128-ECB(md5, salt || 00*8)
 *   block j    = AES-128-ECB(ke, 16 zero bytes with byte[3] = j)
 *   ciphertext = (plaintext || 00) XOR the block stream
 *   mac        = HMAC-SHA1(ka, ciphertext)[0..4]
 *   output     = base41(salt || ciphertext || mac)
 *
 * The trailing NUL byte is encrypted and authenticated: IOS hands the C
 * string terminator to the cipher. Cisco's C reference does this; the
 * encode6.py script beside it does not, so that script does not reproduce
 * device output. This follows the C reference.
 *
 * Mirrors network_secret/cisco_type6.py.
 */

import aesjs from "aes-js";
import { b41Decode, b41Encode } from "../cisco-b41";
import { md5 } from "../md5";
import type { Cipher } from "./types";

const SALT_LEN = 8;
const MAC_LEN = 4;
const BLOCK = 16;
const COUNTER_BYTE = 3;
const MIN_RAW_LEN = SALT_LEN + 1 + MAC_LEN;
// The keystream counter is one byte, so the stream tops out at 256 blocks. One
// byte of the payload is the NUL terminator, so the plaintext gets one less.
const MAX_PLAINTEXT_LEN = 256 * BLOCK - 1;

/**
 * Cast a Uint8Array to BufferSource. TypeScript's DOM lib (>=5.7) narrows
 * BufferSource to ArrayBuffer-backed views, which our plain Uint8Arrays
 * satisfy at runtime but not in the type system.
 */
function buf(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

function aesEcbBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  return new aesjs.ModeOfOperation.ecb(key).encrypt(block);
}

function subkeys(masterKey: string, salt: Uint8Array): [Uint8Array, Uint8Array] {
  const digest = md5(new TextEncoder().encode(masterKey));
  const keInput = new Uint8Array(BLOCK);
  keInput.set(salt);
  keInput[BLOCK - 1] = 1;
  const kaInput = new Uint8Array(BLOCK);
  kaInput.set(salt);
  return [aesEcbBlock(digest, keInput), aesEcbBlock(digest, kaInput)];
}

/** XOR data with the counter-mode keystream. Its own inverse. */
function keystreamXor(ke: Uint8Array, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  let block: Uint8Array = new Uint8Array(BLOCK);
  for (let i = 0; i < data.length; i++) {
    if (i % BLOCK === 0) {
      const counter = new Uint8Array(BLOCK);
      counter[COUNTER_BYTE] = Math.floor(i / BLOCK);
      block = aesEcbBlock(ke, counter);
    }
    out[i] = data[i] ^ block[i % BLOCK];
  }
  return out;
}

async function mac(ka: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    buf(ka),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const tag = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, buf(ciphertext)),
  );
  return tag.subarray(0, MAC_LEN);
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function encode(plaintext: string, key?: string): Promise<string> {
  if (!key) throw new Error("A master key is required");
  const body = new TextEncoder().encode(plaintext);
  if (body.length > MAX_PLAINTEXT_LEN) {
    throw new Error(
      `Plaintext is too long for type 6: at most ${MAX_PLAINTEXT_LEN} bytes`,
    );
  }
  // The trailing NUL is part of the encrypted and authenticated data.
  const data = new Uint8Array(body.length + 1);
  data.set(body);
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const [ke, ka] = subkeys(key, salt);
  const ciphertext = keystreamXor(ke, data);
  const tag = await mac(ka, ciphertext);
  const out = new Uint8Array(SALT_LEN + ciphertext.length + MAC_LEN);
  out.set(salt);
  out.set(ciphertext, SALT_LEN);
  out.set(tag, SALT_LEN + ciphertext.length);
  return b41Encode(out);
}

async function decode(encoded: string, key?: string): Promise<string> {
  if (!key) throw new Error("A master key is required");
  const raw = b41Decode(encoded.trim());
  if (raw.length < MIN_RAW_LEN) {
    throw new Error(
      "Malformed type 6 value: too short to hold a salt, a secret and a MAC",
    );
  }
  if (raw.length - SALT_LEN - MAC_LEN > MAX_PLAINTEXT_LEN + 1) {
    throw new Error(
      `Type 6 value is too long: the secret exceeds ${MAX_PLAINTEXT_LEN} bytes, ` +
        "which the one-byte keystream counter cannot address",
    );
  }
  const salt = raw.subarray(0, SALT_LEN);
  const ciphertext = raw.subarray(SALT_LEN, raw.length - MAC_LEN);
  const tag = raw.subarray(raw.length - MAC_LEN);
  const [ke, ka] = subkeys(key, salt);
  if (!equal(await mac(ka, ciphertext), tag)) {
    throw new Error(
      "Authentication failed: wrong master key, or the value was not produced by this scheme",
    );
  }
  // encode() appends exactly one NUL, so remove exactly one. Stripping every
  // trailing NUL would eat a NUL that is genuinely part of the plaintext, and
  // an unconditional slice would chop a real byte off a value written by an
  // implementation that omits the terminator.
  let plain = keystreamXor(ke, ciphertext);
  if (plain.length > 0 && plain[plain.length - 1] === 0) {
    plain = plain.subarray(0, plain.length - 1);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(plain);
  } catch {
    throw new Error(
      "Decryption produced invalid UTF-8: wrong master key, or a corrupt value",
    );
  }
}

export const ciscoType6: Cipher = {
  id: "cisco-type6",
  name: "Cisco type 6",
  vendor: "Cisco IOS",
  magic: "",
  tagline:
    "IOS's reversible AES format for secrets the device must read back, such as BGP, RADIUS and TACACS keys. Keyed by the device master key.",
  reversible: false,
  keyed: true,
  keyLabel: "Master key",
  status: "available",
  notes: [
    "The master key is the one set with: key config-key password-encrypt. Without it a type 6 value cannot be recovered.",
    "MD5 of the master key gives an AES-128 key. That key derives a per-salt encryption key and a separate authentication key.",
    "The secret is XORed with an AES counter-mode keystream, then tagged with the first 4 bytes of HMAC-SHA1. A wrong master key fails the tag rather than returning garbage.",
    "The whole thing is armoured in base41 over the 41 printable characters that follow 'A', so there is no $6$ marker to recognise.",
    "IOS also encrypts the secret's trailing NUL byte. Implementations that skip it round-trip against themselves but do not match a real device.",
  ],
  example: {
    encoded: "NdUI^_YP[VEPG[MT_bfTEFNZYFCYe\\R\\M",
    plaintext: "password",
    key: "cisco123",
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
  encode,
  decode,
};
