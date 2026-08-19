import { describe, expect, it } from "vitest";
import { b41Decode, b41Encode } from "./cisco-b41";

const hex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

describe("base41", () => {
  it("round-trips an odd-length input", () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    expect(b41Decode(b41Encode(data))).toEqual(data);
  });

  it("round-trips an even-length input", () => {
    const data = new Uint8Array([1, 2, 3, 4]);
    expect(b41Decode(b41Encode(data))).toEqual(data);
  });

  it("emits three symbols per pair plus one pad group", () => {
    expect(b41Encode(new Uint8Array([0, 0, 0, 0])).length).toBe(9);
    expect(b41Encode(new Uint8Array([0, 0, 0])).length).toBe(6);
  });

  it("decodes the salt of Cisco's own vector", () => {
    // The first 12 symbols of the published type 6 vector carry the 8-byte salt.
    const vector = "NdUI^_YP[VEPG[MT_bfTEFNZYFCYe\\R\\M";
    const raw = b41Decode(vector);
    expect(raw.length).toBe(21); // 8 salt + 9 ciphertext + 4 mac
    expect(hex(raw.slice(0, 8))).toBe("5b0c394ba0198a98");
    expect(b41Encode(raw)).toBe(vector);
  });

  it("rejects a length that is not a multiple of three", () => {
    expect(() => b41Decode("AAAA")).toThrow();
  });

  it("rejects a symbol outside the alphabet", () => {
    expect(() => b41Decode("AA!")).toThrow();
  });

  it("rejects a group above 65535", () => {
    expect(() => b41Decode("iii".repeat(7))).toThrow();
  });

  it("rejects an empty string", () => {
    expect(() => b41Decode("")).toThrow();
  });

  it("rejects empty input to encode", () => {
    expect(() => b41Encode(new Uint8Array(0))).toThrow("Nothing to encode");
  });
});
