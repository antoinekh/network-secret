/**
 * Shared SHA-crypt implementation for the "$5$"/"$6$" password formats.
 *
 * "$5$" (sha256-crypt) and "$6$" (sha512-crypt) are the same algorithm
 * parameterised only by which hash function feeds it, so it is implemented
 * once here and passed a hash name, exactly as `cisco-hash.ts` shares
 * framing between Cisco type 8 and type 9 and takes a KDF.
 *
 * Spec: Ulrich Drepper, "Unix crypt using SHA-256 and SHA-512"
 * (https://www.akkadia.org/drepper/SHA-crypt.txt). The digest is produced by
 * a long chain of intermediate hashes (digests A/B/DP/DS feeding a
 * `rounds`-long loop over digest C), then encoded with a base64 variant
 * unrelated to standard base64 or to Cisco's variant in `cisco-b64.ts`:
 * 3-byte groups become 4 characters using little-endian bit order within the
 * group, and the byte that fills each of the three group positions is
 * picked by a shuffled, variant-specific permutation rather than taken in
 * sequence.
 *
 * Ported from `network_secret/_sha_crypt.py` on this branch, including its
 * permutation tables verbatim; both are verified byte-for-byte against
 * `openssl passwd -5`/`-6` output via the shared known-answer vectors in
 * `juniper-encrypted-password.test.ts` and `sha-crypt.test.ts`.
 *
 * Web Crypto's `crypto.subtle.digest` only hashes a whole buffer at once (no
 * incremental `update`), unlike Python's `hashlib`, so every intermediate
 * hash here is built by concatenating byte arrays first and hashing the
 * result in one call. The `rounds`-long loop over digest C therefore issues
 * `rounds` sequential `await`ed digest calls; being async lets this yield to
 * the event loop between rounds, so a caller's "working" UI state can still
 * paint instead of freezing the tab for the whole computation.
 *
 * This module performs no bounds checking on `rounds` - the caller
 * (`ciphers/juniper-encrypted-password.ts`) must enforce
 * MIN_ROUNDS/MAX_ROUNDS *before* calling `hashPassword`, since `rounds` here
 * is a plain multiplier on the amount of hashing work done.
 */

export const ALPHABET =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
export const SALT_LEN = 16; // characters generated for a fresh salt

export type HashName = "SHA-256" | "SHA-512";

const DIGEST_SIZES: Record<HashName, number> = { "SHA-256": 32, "SHA-512": 64 };

// Byte-index permutations feeding b64From24bit(b2, b1, b0, n), taken from
// Drepper's reference sha256-crypt.c / sha512-crypt.c via _sha_crypt.py.
// Each 3-tuple names which digest byte fills the high/mid/low position of
// one 3-byte group.
const SHA256_GROUPS: readonly (readonly [number, number, number])[] = [
  [0, 10, 20], [21, 1, 11], [12, 22, 2], [3, 13, 23], [24, 4, 14],
  [15, 25, 5], [6, 16, 26], [27, 7, 17], [18, 28, 8], [9, 19, 29],
];
// Final, partial group: 3 output characters.
const SHA256_LAST: readonly [number | null, number | null, number] = [null, 31, 30];

const SHA512_GROUPS: readonly (readonly [number, number, number])[] = [
  [0, 21, 42], [22, 43, 1], [44, 2, 23], [3, 24, 45], [25, 46, 4],
  [47, 5, 26], [6, 27, 48], [28, 49, 7], [50, 8, 29], [9, 30, 51],
  [31, 52, 10], [53, 11, 32], [12, 33, 54], [34, 55, 13], [56, 14, 35],
  [15, 36, 57], [37, 58, 16], [59, 17, 38], [18, 39, 60], [40, 61, 19],
  [62, 20, 41],
];
// Final, partial group: 2 output characters.
const SHA512_LAST: readonly [number | null, number | null, number] = [null, null, 63];

/**
 * Cast a Uint8Array to BufferSource. TypeScript's DOM lib (>=5.7) narrows
 * BufferSource to ArrayBuffer-backed views, which our plain Uint8Arrays
 * satisfy at runtime but not in the type system.
 */
function buf(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

/** Encode one 3-byte group (b2 high, b0 low) as n base64 characters.
 *
 * Unlike standard base64, the 6-bit groups are emitted low-order first.
 */
function b64From24bit(b2: number, b1: number, b0: number, n: number): string {
  let word = (b2 << 16) | (b1 << 8) | b0;
  let chars = "";
  for (let i = 0; i < n; i++) {
    chars += ALPHABET[word & 0x3f];
    word >>= 6;
  }
  return chars;
}

/** Encode a raw sha256/sha512 digest with SHA-crypt's base64 variant. */
export function encodeDigest(digest: Uint8Array, hashName: HashName): string {
  const groups = hashName === "SHA-256" ? SHA256_GROUPS : SHA512_GROUPS;
  const last = hashName === "SHA-256" ? SHA256_LAST : SHA512_LAST;
  const lastN = hashName === "SHA-256" ? 3 : 2;
  let out = "";
  for (const [b2, b1, b0] of groups) {
    out += b64From24bit(digest[b2], digest[b1], digest[b0], 4);
  }
  const [lb2, lb1, lb0] = last;
  out += b64From24bit(
    lb2 === null ? 0 : digest[lb2],
    lb1 === null ? 0 : digest[lb1],
    digest[lb0],
    lastN,
  );
  return out;
}

/** Return a fresh `length`-character salt drawn from the crypt alphabet. */
export function generateSalt(length: number = SALT_LEN): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = "";
  for (let i = 0; i < length; i++) {
    // ALPHABET.length is 64 = 2**6, so masking a byte's low 6 bits is
    // unbiased - no rejection sampling needed.
    out += ALPHABET[bytes[i] & 0x3f];
  }
  return out;
}

async function sha(hashName: HashName, data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(hashName, buf(data));
  return new Uint8Array(digest);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Repeat `chunk` end-to-end and truncate to exactly `length` bytes. */
function repeatToLength(chunk: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = chunk[i % chunk.length];
  }
  return out;
}

/**
 * Compute the raw SHA-crypt digest for `password`/`salt`/`rounds`.
 *
 * `rounds` is used exactly as given, with no bounds enforced here - see the
 * module docstring.
 */
export async function hashPassword(
  password: string,
  salt: string,
  rounds: number,
  hashName: HashName,
): Promise<Uint8Array> {
  const digestSize = DIGEST_SIZES[hashName];
  const pw = new TextEncoder().encode(password);
  const slt = new TextEncoder().encode(salt);
  const plen = pw.length;
  const slen = slt.length;

  const digestB = await sha(hashName, concatBytes(pw, slt, pw));

  const aParts: Uint8Array[] = [pw, slt, repeatToLength(digestB, plen)];
  {
    let remaining = plen;
    while (remaining > 0) {
      aParts.push(remaining & 1 ? digestB : pw);
      remaining >>>= 1;
    }
  }
  const digestA = await sha(hashName, concatBytes(...aParts));

  const dpParts: Uint8Array[] = [];
  for (let i = 0; i < plen; i++) dpParts.push(pw);
  const digestDp = await sha(hashName, concatBytes(...dpParts));
  const pBytes = repeatToLength(digestDp, plen);

  const dsParts: Uint8Array[] = [];
  const dsCount = 16 + digestA[0];
  for (let i = 0; i < dsCount; i++) dsParts.push(slt);
  const digestDs = await sha(hashName, concatBytes(...dsParts));
  const sBytes = repeatToLength(digestDs, slen);

  let digestC = digestA;
  for (let roundNum = 0; roundNum < rounds; roundNum++) {
    const parts: Uint8Array[] = [];
    parts.push(roundNum % 2 ? pBytes : digestC);
    if (roundNum % 3) parts.push(sBytes);
    if (roundNum % 7) parts.push(pBytes);
    parts.push(roundNum % 2 ? digestC : pBytes);
    digestC = await sha(hashName, concatBytes(...parts));
  }

  return digestC;
}
