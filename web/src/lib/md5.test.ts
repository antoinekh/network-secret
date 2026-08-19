import { describe, expect, it } from "vitest";
import { md5 } from "./md5";

const hex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const bytes = (s: string) => new TextEncoder().encode(s);

describe("md5", () => {
  // RFC 1321 test suite.
  it.each([
    ["", "d41d8cd98f00b204e9800998ecf8427e"],
    ["a", "0cc175b9c0f1b6a831c399e269772661"],
    ["abc", "900150983cd24fb0d6963f7d28e17f72"],
    ["message digest", "f96b697d7cb7938d525a2f31aaf161d0"],
    ["abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"],
    [
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "57edf4a22be3c955ac49da2e2107b67a",
    ],
  ])("hashes %j", (input, expected) => {
    expect(hex(md5(bytes(input)))).toBe(expected);
  });

  it("handles a 56-byte input, where padding spills into a second block", () => {
    expect(hex(md5(bytes("a".repeat(56))))).toBe("3b0c8ac703f828b04c6c197006d17218");
  });

  it("matches the key derivation used by Cisco type 6", () => {
    // This exact digest is the AES-128 key that cisco-type6.ts depends on.
    expect(hex(md5(bytes("cisco123")))).toBe("07982c55db2b9985d3391f02e639db9c");
  });
});
