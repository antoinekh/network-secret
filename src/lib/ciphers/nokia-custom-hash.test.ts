import { describe, expect, it } from "vitest";
import { decode, encode } from "./nokia-custom-hash";

// Known-answer vector from the SR OS consistent-hashing lab (encrypt_key.py).
const KEY = "a3f8d9e112c04b7af1c3e8b92d057a4e"; // 32 chars -> AES-256
const PLAIN = "L@bS3cr3t!";
const ENCODED = "Xfs39BMeblOtlorgwTChxQ== custom";

const ROUNDTRIP = ["a", "L@bS3cr3t!", "LabBgpSecret1", "café", ""];

describe("nokia custom-hash", () => {
  it("encodes the known lab vector", async () => {
    expect(await encode(PLAIN, KEY)).toBe(ENCODED);
  });

  it("decodes the known lab vector (with ' custom' suffix)", async () => {
    expect(await decode(ENCODED, KEY)).toBe(PLAIN);
  });

  it("decodes a bare base64 value (no suffix)", async () => {
    expect(await decode("Xfs39BMeblOtlorgwTChxQ==", KEY)).toBe(PLAIN);
  });

  it("is deterministic (ECB): same input -> same output", async () => {
    expect(await encode(PLAIN, KEY)).toBe(await encode(PLAIN, KEY));
  });

  it.each(ROUNDTRIP)("round-trips %j", async (plaintext) => {
    expect(await decode(await encode(plaintext, KEY), KEY)).toBe(plaintext);
  });

  it("works with a 16-char key (AES-128)", async () => {
    const k = "0123456789abcdef";
    expect(await decode(await encode("hello", k), k)).toBe("hello");
  });

  it("rejects a key of the wrong length", async () => {
    await expect(encode("x", "tooshort")).rejects.toThrow(/16, 24, or 32/);
  });

  it("requires a key", async () => {
    await expect(encode("x")).rejects.toThrow(/shared AES key/);
    await expect(decode(ENCODED)).rejects.toThrow(/shared AES key/);
  });

  it("rejects a wrong key", async () => {
    await expect(decode(ENCODED, "00000000000000000000000000000000")).rejects.toThrow(
      /Decryption failed/,
    );
  });

  it("rejects a ciphertext of invalid length", async () => {
    await expect(decode("YWJj", KEY)).rejects.toThrow(/block size/);
  });
});
