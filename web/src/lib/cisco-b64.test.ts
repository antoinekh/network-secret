import { describe, expect, it } from "vitest";
import { CISCO_ALPHABET, ciscoBase64 } from "./cisco-b64";

describe("ciscoBase64", () => {
  it("encodes 32 bytes to 43 unpadded characters", () => {
    const out = ciscoBase64(new Uint8Array(32));
    expect(out).toHaveLength(43);
    expect(out).not.toContain("=");
  });

  it("uses only the Cisco alphabet", () => {
    const out = ciscoBase64(Uint8Array.from({ length: 32 }, (_, i) => i * 7));
    expect([...out].every((c) => CISCO_ALPHABET.includes(c))).toBe(true);
  });

  it("maps all-zero bytes to the first alphabet character", () => {
    expect(ciscoBase64(new Uint8Array(32))).toBe(".".repeat(43));
  });
});
