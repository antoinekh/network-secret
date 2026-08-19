import { describe, expect, it } from "vitest";
import { CISCO_ALPHABET } from "./cisco-b64";
import { generateSalt, parseHash, validateSalt } from "./cisco-hash";

describe("cisco hash framing", () => {
  it("generates a 14-character salt from the Cisco alphabet", () => {
    const salt = generateSalt();
    expect(salt).toHaveLength(14);
    expect([...salt].every((c) => CISCO_ALPHABET.includes(c))).toBe(true);
  });

  it("splits a well-formed hash", () => {
    expect(parseHash("$8$abc$def", 8)).toEqual({ salt: "abc", encoded: "def" });
  });

  it.each(["$", "a b", ""])("rejects the salt %j", (salt) => {
    expect(() => validateSalt(salt)).toThrow();
  });

  it("rejects a hash of the wrong type", () => {
    expect(() => parseHash("$9$abc$def", 8)).toThrow();
  });

  // validateSalt rejects four conditions: empty, '$', space, non-ASCII, and
  // non-printable. The '$' and space cases are covered above; a '$' embedded
  // in a full hash string would trip parseHash's field-count check first, so
  // these go straight at validateSalt to pin each branch individually.
  it.each(["café", "salt\x00null", "salt\x1fcontrol"])(
    "rejects the salt %j (non-ASCII / non-printable)",
    (salt) => {
      expect(() => validateSalt(salt)).toThrow();
    },
  );

  it("accepts a valid salt whose length is not 14 (length is deliberately not checked)", () => {
    expect(validateSalt("abc")).toBe("abc");
    expect(validateSalt("abcdefghijklmnopqrstuvwxyz")).toBe(
      "abcdefghijklmnopqrstuvwxyz",
    );
  });
});
