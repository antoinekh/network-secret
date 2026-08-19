import bcrypt from "bcryptjs";
import { describe, expect, it } from "vitest";
import { nokiaSrosPassword } from "./nokia-sros-password";

const VECTOR_PASSWORD = "lab123";
const VECTOR_HASH =
  "$2y$10$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe";

describe("nokia sros password", () => {
  it("verifies the known-answer vector", async () => {
    expect(await nokiaSrosPassword.verify!(VECTOR_HASH, VECTOR_PASSWORD)).toBe(true);
  });

  it("rejects the wrong password", async () => {
    expect(await nokiaSrosPassword.verify!(VECTOR_HASH, "wrong")).toBe(false);
  });

  it.each(["$2a$", "$2b$", "$2y$"])("verifies the %s prefix", async (prefix) => {
    const value = prefix + VECTOR_HASH.slice("$2y$".length);
    expect(await nokiaSrosPassword.verify!(value, VECTOR_PASSWORD)).toBe(true);
  });

  it("hashes with a fresh salt each call and always emits $2y$", async () => {
    const a = await nokiaSrosPassword.encode(VECTOR_PASSWORD);
    const b = await nokiaSrosPassword.encode(VECTOR_PASSWORD);
    expect(a).not.toBe(b);
    expect(a.startsWith("$2y$")).toBe(true);
    expect(b.startsWith("$2y$")).toBe(true);
  });

  it("verifies a hash it produced", async () => {
    const value = await nokiaSrosPassword.encode("L@bS3cr3t!");
    expect(await nokiaSrosPassword.verify!(value, "L@bS3cr3t!")).toBe(true);
  });

  it("is marked one-way and its decode throws", async () => {
    expect(nokiaSrosPassword.oneWay).toBe(true);
    await expect(nokiaSrosPassword.decode(VECTOR_HASH)).rejects.toThrow(
      /cannot be decoded/,
    );
  });

  it.each([
    "",
    "not-a-hash",
    "lab123",
    "$8$J5J/1K3e8gk974$HRezVpnMZOhOU2uxFTv.79S1U1PpMScizwXS3Z1Dx1s", // Cisco type 8
    "$2y$10$jBwKMP7r.vf4x1tbThl7Y.", // truncated: salt only, no digest field
    "$2y$10$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUo", // truncated digest
    "$2y$xx$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe", // non-numeric cost
    "$2z$10$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe", // unrecognised prefix
  ])("rejects malformed input %j", async (value) => {
    await expect(nokiaSrosPassword.verify!(value, VECTOR_PASSWORD)).rejects.toThrow();
  });

  it("rejects an out-of-range cost", async () => {
    const value = "$2y$99$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe";
    await expect(nokiaSrosPassword.verify!(value, VECTOR_PASSWORD)).rejects.toThrow(
      /bcrypt cost out of range \(4-16\): 99/,
    );
  });

  it.each([17, 31])(
    "rejects a cost of %i (above MAX_COST) quickly, before ever calling into bcryptjs",
    async (cost) => {
      // Cost 31 takes on the order of hundreds of hours to actually hash (bcrypt's
      // cost is an exponent). If a future refactor moved the range check after the
      // call into bcryptjs, this test would hang instead of failing fast, so the
      // timing assertion is the point, not just rejects.toThrow.
      const value = `$2y$${cost}$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe`;
      const started = performance.now();
      await expect(nokiaSrosPassword.verify!(value, VECTOR_PASSWORD)).rejects.toThrow(
        new RegExp(`bcrypt cost out of range \\(4-16\\): ${cost}`),
      );
      expect(performance.now() - started).toBeLessThan(500);
    },
  );

  it.each([
    "$2y$4$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe", // one digit
    "$2y$004$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe", // three digits
    "$2y$1a$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe", // not both digits
    "$2y$$jBwKMP7r.vf4x1tbThl7Y.iBIgdDpv8WZ4DTgrnNIZdJS97NUorVe", // empty cost field
  ])("rejects a cost that is not exactly two digits: %j", async (value) => {
    // Real bcrypt always zero-pads the cost to two digits, so an unpadded or
    // over-padded cost is a malformed value, not just a low- or high-cost one.
    await expect(nokiaSrosPassword.verify!(value, VECTOR_PASSWORD)).rejects.toThrow(
      /exactly two digits/,
    );
  });

  it("still accepts a genuine zero-padded low cost", async () => {
    // "$2y$04$..." is what real bcrypt actually emits for cost 4 (MIN_COST);
    // the two-digit requirement must not narrow what real bcrypt produces.
    const salt = "$2y$04$jBwKMP7r.vf4x1tbThl7Y.";
    const hash = await bcrypt.hash(VECTOR_PASSWORD, salt);
    expect(hash.startsWith("$2y$04$")).toBe(true);
    expect(await nokiaSrosPassword.verify!(hash, VECTOR_PASSWORD)).toBe(true);
  });
});
