import { describe, expect, it } from "vitest";
import { ALPHABET, encodeDigest, generateSalt, hashPassword } from "./sha-crypt";

const PASSWORD = "lab123";

// Both cross-checked against `openssl passwd` (see
// ciphers/juniper-encrypted-password.test.ts for the full vector table).
describe("sha-crypt", () => {
  it("matches the $5$ (sha256-crypt) known-answer vector", async () => {
    const digest = await hashPassword(PASSWORD, "itHMToxg", 5000, "SHA-256");
    expect(encodeDigest(digest, "SHA-256")).toBe(
      "IAeDKDuWsSCoL2W7fognCW8cyNj4YE9ZhDvCoWFC5y/",
    );
  });

  it("matches the $6$ (sha512-crypt) known-answer vector", async () => {
    const digest = await hashPassword(PASSWORD, "OV3tvDvc", 5000, "SHA-512");
    expect(encodeDigest(digest, "SHA-512")).toBe(
      "QT3FzP8LWnxLDCfDLKibn1.EzGS5crupCiea7Kbi2W4Y9Z1kYu9EYTxs/z344U8Mwh4QtwlnbUiLZWUHyhrZl1",
    );
  });

  it("draws generateSalt from the crypt alphabet at the requested length", () => {
    const salt = generateSalt();
    expect(salt).toHaveLength(16);
    for (const ch of salt) expect(ALPHABET.includes(ch)).toBe(true);
  });

  it("generateSalt is different across calls", () => {
    expect(generateSalt()).not.toBe(generateSalt());
  });
});
