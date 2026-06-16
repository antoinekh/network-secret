import { describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64 } from "./base64";

describe("base64", () => {
  it("round-trips arbitrary bytes", () => {
    for (let len = 0; len < 40; len++) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = (i * 37 + 11) % 256;
      expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
    }
  });

  it("emits no padding by default", () => {
    expect(bytesToBase64(new Uint8Array([1]))).not.toContain("=");
    expect(bytesToBase64(new Uint8Array([1, 2]))).not.toContain("=");
  });

  it("emits padding when asked", () => {
    expect(bytesToBase64(new Uint8Array([1]), true)).toBe("AQ==");
    expect(bytesToBase64(new Uint8Array([1, 2]), true)).toBe("AQI=");
  });

  it("decodes unpadded input", () => {
    // "salt" field from a real $8$ value: 11 chars -> 8 bytes
    expect(base64ToBytes("p8XEvHtxRNE").length).toBe(8);
  });

  it("throws on invalid base64", () => {
    expect(() => base64ToBytes("!!!!")).toThrow(/Invalid base64/);
  });
});
