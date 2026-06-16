import { describe, expect, it } from "vitest";
import { decode, encode } from "./juniper9";

const KNOWN: Array<[string, string]> = [
  ["$9$FNkC3/t1IcevLuOWx", "hello"],
  ["$9$a1Gjk5Qnp0I.P0IEcvMaZUjP5Ctu", "Juniper99"],
];

const ROUNDTRIP = [
  "a",
  "hello",
  "L@bS3cr3t!",
  "LabBgpSecret1",
  "0123456789",
  "abcdefghijklmnopqrstuvwxyz",
  "!@#$%^&*()_+-=[]{}|;':\",./<>?",
  "café",
];

describe("juniper9", () => {
  it.each(KNOWN)("decodes known vector %s", (encoded, expected) => {
    expect(decode(encoded)).toBe(expected);
  });

  it.each(ROUNDTRIP)("round-trips %j", (plaintext) => {
    expect(decode(encode(plaintext))).toBe(plaintext);
  });

  it("ignores surrounding whitespace", () => {
    expect(decode("  $9$FNkC3/t1IcevLuOWx\n")).toBe("hello");
  });

  it("encode starts with $9$", () => {
    expect(encode("hello").startsWith("$9$")).toBe(true);
  });

  it("encode is non-deterministic", () => {
    const results = new Set(Array.from({ length: 20 }, () => encode("test")));
    expect(results.size).toBeGreaterThan(1);
  });

  it("rejects a missing magic prefix", () => {
    expect(() => decode("plaintext")).toThrow(/\$9\$/);
  });

  it("rejects an empty payload", () => {
    expect(() => decode("$9$")).toThrow(/Empty/);
  });

  it("rejects an invalid start character", () => {
    expect(() => decode("$9$~~~~~")).toThrow(/start character/);
  });

  it("rejects a truncated ciphertext", () => {
    expect(() => decode(encode("hello").slice(0, -1))).toThrow(/[Tt]runcated/);
  });

  it("rejects non-Latin-1 plaintext", () => {
    expect(() => encode("€")).toThrow(/single-byte/);
  });
});
