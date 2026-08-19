/**
 * base41, the armour Cisco type 6 uses.
 *
 * Two bytes become three symbols, most significant first, over the 41
 * printable characters that follow ASCII 'A'. After the whole pairs, one pad
 * group is appended: it carries the odd trailing byte when the input length
 * is odd, and the marker (0x00, 0x01) when it is even.
 */

export const B41_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghi";
const BASE = 41;
const GROUP = 3;
const MAX_PAIR = 0xffff;

export function b41Encode(data: Uint8Array): string {
  if (data.length === 0) throw new Error("Nothing to encode");
  const pairs: [number, number][] = [];
  const whole = data.length - (data.length % 2);
  for (let i = 0; i < whole; i += 2) pairs.push([data[i], data[i + 1]]);
  pairs.push(data.length % 2 ? [data[data.length - 1], 0] : [0, 1]);

  let out = "";
  for (const [hi, lo] of pairs) {
    const n = (hi << 8) | lo;
    out +=
      B41_ALPHABET[Math.floor(n / (BASE * BASE))] +
      B41_ALPHABET[Math.floor(n / BASE) % BASE] +
      B41_ALPHABET[n % BASE];
  }
  return out;
}

export function b41Decode(text: string): Uint8Array {
  if (text.length === 0) throw new Error("Empty type 6 value");
  if (text.length % GROUP !== 0) {
    throw new Error(
      `Malformed type 6 value: length ${text.length} is not a multiple of ${GROUP}`,
    );
  }
  const out = new Uint8Array((text.length / GROUP) * 2);
  for (let i = 0; i < text.length; i += GROUP) {
    let n = 0;
    for (let j = 0; j < GROUP; j++) {
      const index = B41_ALPHABET.indexOf(text[i + j]);
      if (index < 0) {
        throw new Error(
          `Character '${text[i + j]}' is not in the type 6 base41 alphabet`,
        );
      }
      n = n * BASE + index;
    }
    if (n > MAX_PAIR) {
      throw new Error(
        `Group '${text.slice(i, i + GROUP)}' decodes to ${n}, which does not fit in two bytes`,
      );
    }
    const at = (i / GROUP) * 2;
    out[at] = n >> 8;
    out[at + 1] = n & 0xff;
  }
  // The final group is the pad. A non-zero last byte marks the even-length
  // form, so drop both bytes; otherwise keep the carried byte.
  return out.slice(0, out.length - (out[out.length - 1] ? 2 : 1));
}
