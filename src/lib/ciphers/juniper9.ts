/**
 * Juniper $9$ reversible "encryption".
 *
 * $9$ is a keyless, device-independent substitution cipher: a value encoded on
 * one Juniper device decodes on any other with no node-specific secret. It is
 * obfuscation, not cryptography - anyone with this code can recover the
 * plaintext. Ported from the public Crypt::Juniper / junosdecode algorithm.
 */

import type { Cipher } from "./types";

const MAGIC = "$9$";
const FAMILY = [
  "QzF3n6/9CAtpu0O",
  "B1IREhcSyrleKvMW8LXx",
  "7N-dVbwsY2g4oaJZGUDj",
  "iHkq.mPf5T",
];
const ALPHA = FAMILY.join("");
const SIZE = ALPHA.length;

const NUM: Record<string, number> = {};
for (let i = 0; i < ALPHA.length; i++) {
  NUM[ALPHA[i]] = i;
}

const EXTRA: Record<string, number> = {};
FAMILY.forEach((family, i) => {
  for (const c of family) {
    EXTRA[c] = 3 - i;
  }
});

const ENCODING = [
  [1, 4, 32],
  [1, 16, 32],
  [1, 8, 32],
  [1, 64],
  [1, 32],
  [1, 4, 16, 128],
  [1, 32, 64],
];

/** Positive modulo (JS `%` keeps the sign of the dividend). */
function mod(a: number, n: number): number {
  return ((a % n) + n) % n;
}

function gap(c1: string, c2: string): number {
  return mod(NUM[c2] - NUM[c1], SIZE) - 1;
}

export function decode(encoded: string): string {
  encoded = encoded.trim();
  if (!encoded.startsWith(MAGIC)) {
    throw new Error("Not a Juniper $9$ string: must start with $9$");
  }
  let chars = encoded.slice(MAGIC.length);
  if (chars.length === 0) {
    throw new Error("Empty $9$ payload");
  }
  const first = chars[0];
  if (!(first in NUM)) {
    throw new Error(`Invalid start character '${first}': not in $9$ alphabet`);
  }
  chars = chars.slice(1 + EXTRA[first]);
  let prev = first;
  const result: string[] = [];
  while (chars.length > 0) {
    const weights = ENCODING[result.length % ENCODING.length];
    const group = chars.slice(0, weights.length);
    if (group.length < weights.length) {
      throw new Error("Truncated $9$ ciphertext: incomplete final character group");
    }
    chars = chars.slice(weights.length);
    let val = 0;
    for (let k = 0; k < weights.length; k++) {
      const c = group[k];
      if (!(c in NUM)) {
        throw new Error(`Character '${c}' not in $9$ alphabet: ciphertext may be invalid`);
      }
      val += gap(prev, c) * weights[k];
      prev = c;
    }
    result.push(String.fromCharCode(mod(val, 256)));
  }
  return result.join("");
}

export function encode(plaintext: string): string {
  const randChar = () => ALPHA[Math.floor(Math.random() * SIZE)];
  const start = randChar();
  const result: string[] = [MAGIC, start];
  for (let i = 0; i < EXTRA[start]; i++) {
    result.push(randChar());
  }
  let prev = start;
  for (let i = 0; i < plaintext.length; i++) {
    const weights = ENCODING[i % ENCODING.length];
    let val = plaintext.charCodeAt(i);
    if (val > 255) {
      throw new Error(
        `Character '${plaintext[i]}' cannot be $9$-encoded: only single-byte (Latin-1) characters are supported`,
      );
    }
    const gaps: number[] = [];
    for (let j = weights.length - 1; j >= 0; j--) {
      gaps.push(Math.floor(val / weights[j]));
      val = val % weights[j];
    }
    gaps.reverse();
    for (const g of gaps) {
      const c = ALPHA[mod(NUM[prev] + g + 1, SIZE)];
      result.push(c);
      prev = c;
    }
  }
  return result.join("");
}

export const juniper9: Cipher = {
  id: "juniper9",
  index: "01",
  name: "Juniper $9$",
  vendor: "Juniper",
  magic: "$9$",
  tagline: "Juniper type 9 ($9$): reversible, keyless obfuscation for JUNOS secrets.",
  reversible: true,
  keyed: false,
  status: "available",
  notes: [
    "$9$ is a substitution cipher, not real cryptography: it is reversible by anyone, with no key.",
    "It is device-independent - a value encoded on one Juniper box decodes on any other.",
    "Encoding is non-deterministic: random filler means the same plaintext yields a different $9$ string each time.",
    "Treat it as obfuscation against shoulder-surfing, never as protection.",
  ],
  example: {
    encoded: "$9$FNkC3/t1IcevLuOWx",
    plaintext: "hello",
  },
  links: [
    {
      label: "github.com/antoinekh/juniper9-crypt",
      url: "https://github.com/antoinekh/juniper9-crypt",
      note: "Python library & CLI, plus the documented algorithm.",
    },
  ],
  encode: async (plaintext) => encode(plaintext),
  decode: async (encoded) => decode(encoded),
};
