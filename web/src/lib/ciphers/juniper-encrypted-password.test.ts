import { describe, expect, it, beforeAll } from "vitest";
import {
  DEFAULT_ROUNDS,
  MAGIC_SHA256,
  MAGIC_SHA512,
  MAX_ROUNDS,
  MIN_ROUNDS,
  SECRET_DATA_MARKER,
  VARIANTS,
  decode,
  encode,
  encryptWithSalt,
  juniperEncryptedPassword,
  verify,
} from "./juniper-encrypted-password";

// Mirrors tests/test_juniper_encrypted_password.py on this branch: both
// suites check the same behaviour against the same known-answer vectors.

const VECTOR_PASSWORD = "lab123";
// Real value from a device.
const VECTOR_SHA256 = "$5$itHMToxg$IAeDKDuWsSCoL2W7fognCW8cyNj4YE9ZhDvCoWFC5y/";
// Generated with `openssl passwd -6 -salt OV3tvDvc lab123`.
const VECTOR_SHA512 =
  "$6$OV3tvDvc$QT3FzP8LWnxLDCfDLKibn1.EzGS5crupCiea7Kbi2W4Y9Z1kYu9EYTxs/" +
  "z344U8Mwh4QtwlnbUiLZWUHyhrZl1";

describe("juniper encrypted-password: known-answer vectors", () => {
  it("verifies the sha256-crypt vector", async () => {
    expect(await verify(VECTOR_SHA256, VECTOR_PASSWORD)).toBe(true);
  });

  it("verifies the sha512-crypt vector", async () => {
    expect(await verify(VECTOR_SHA512, VECTOR_PASSWORD)).toBe(true);
  });

  it("encryptWithSalt reproduces the sha256-crypt vector", async () => {
    expect(await encryptWithSalt(VECTOR_PASSWORD, "$5$itHMToxg")).toBe(VECTOR_SHA256);
  });

  it("encryptWithSalt reproduces the sha512-crypt vector", async () => {
    expect(await encryptWithSalt(VECTOR_PASSWORD, "$6$OV3tvDvc")).toBe(VECTOR_SHA512);
  });

  it("rejects the wrong password", async () => {
    expect(await verify(VECTOR_SHA256, "wrong")).toBe(false);
  });
});

describe("juniper encrypted-password: encode()", () => {
  it("defaults to $6$ and draws a fresh salt each call", async () => {
    const a = await encode(VECTOR_PASSWORD);
    const b = await encode(VECTOR_PASSWORD);
    expect(a).not.toBe(b);
    expect(a.startsWith(MAGIC_SHA512)).toBe(true);
    expect(b.startsWith(MAGIC_SHA512)).toBe(true);
  });
});

describe("juniper encrypted-password: variant parameter", () => {
  // Mirrors tests/test_juniper_encrypted_password.py's "variant parameter"
  // section: both suites check the same behaviour against the same rules.

  it("encode with no variant emits $6$", async () => {
    const value = await encode(VECTOR_PASSWORD);
    expect(value.startsWith(MAGIC_SHA512)).toBe(true);
  });

  it("encode with variant sha256 emits $5$", async () => {
    const value = await encode(VECTOR_PASSWORD, undefined, "sha256");
    expect(value.startsWith(MAGIC_SHA256)).toBe(true);
  });

  it("encode with variant sha512 emits $6$", async () => {
    const value = await encode(VECTOR_PASSWORD, undefined, "sha512");
    expect(value.startsWith(MAGIC_SHA512)).toBe(true);
  });

  it("the sha256 variant with the owner's real salt reproduces the real device vector byte for byte", async () => {
    const value = await encryptWithSalt(VECTOR_PASSWORD, "$5$itHMToxg", "sha256");
    expect(value).toBe(VECTOR_SHA256);
    expect(value).toBe("$5$itHMToxg$IAeDKDuWsSCoL2W7fognCW8cyNj4YE9ZhDvCoWFC5y/");
  });

  it("a variant agreeing with the salt's prefix is accepted", async () => {
    const value = await encryptWithSalt(VECTOR_PASSWORD, "$6$abcdefgh", "sha512");
    expect(value.startsWith("$6$abcdefgh$")).toBe(true);
  });

  it("a variant conflicting with the salt's prefix raises, naming both", async () => {
    await expect(
      encryptWithSalt(VECTOR_PASSWORD, "$5$abcdefgh", "sha512"),
    ).rejects.toThrow(/sha512/);
    try {
      await encryptWithSalt(VECTOR_PASSWORD, "$5$abcdefgh", "sha512");
      throw new Error("expected encryptWithSalt to throw");
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      expect(message).toContain("sha512");
      expect(message).toContain("$5$abcdefgh");
    }
  });

  it("a variant with an unprefixed salt selects the variant", async () => {
    const value = await encryptWithSalt(VECTOR_PASSWORD, "abcdefgh", "sha256");
    expect(value.startsWith("$5$abcdefgh$")).toBe(true);
  });

  it("an unknown variant raises", async () => {
    await expect(encode(VECTOR_PASSWORD, undefined, "sha1")).rejects.toThrow(/sha1/);
  });

  it("VARIANTS defaults to sha512 first", () => {
    expect(VARIANTS[0]).toBe("sha512");
    expect(new Set(VARIANTS)).toEqual(new Set(["sha512", "sha256"]));
  });
});

describe("juniper encrypted-password: catalogue entry declares variants", () => {
  it("declares variants with $6$ sha512 first, so the default cannot silently flip", () => {
    expect(juniperEncryptedPassword.variants).toBeDefined();
    expect(juniperEncryptedPassword.variants?.[0]?.value).toBe("sha512");
    expect(juniperEncryptedPassword.variants?.map((v) => v.value)).toEqual([
      "sha512",
      "sha256",
    ]);
  });
});

describe("juniper encrypted-password: round trips and rounds= form", () => {
  // Low, explicit rounds counts keep this suite fast: the values used here
  // are only exercising parsing/formatting mechanics, not the real device
  // default (covered above against real vectors), so there is no reason to
  // pay DEFAULT_ROUNDS's cost repeatedly.
  it.each([MAGIC_SHA256, MAGIC_SHA512])("round-trips both variants (%s)", async (magic) => {
    const value = await encryptWithSalt("L@bS3cr3t!", `${magic}rounds=1000$abcdefgh`);
    expect(value.startsWith(magic)).toBe(true);
    expect(await verify(value, "L@bS3cr3t!")).toBe(true);
    expect(await verify(value, "wrong")).toBe(false);
  });

  it("bare salt selects the default variant and rounds", async () => {
    const value = await encryptWithSalt(VECTOR_PASSWORD, "abcdefgh");
    expect(value.startsWith(MAGIC_SHA512)).toBe(true);
    expect(value.includes("rounds=")).toBe(false);
    expect(await verify(value, VECTOR_PASSWORD)).toBe(true);
  });

  it("the rounds= form is honoured and round-trips", async () => {
    const value = await encryptWithSalt(VECTOR_PASSWORD, "$6$rounds=1200$abcdefgh");
    expect(value.startsWith("$6$rounds=1200$abcdefgh$")).toBe(true);
    expect(await verify(value, VECTOR_PASSWORD)).toBe(true);
    expect(await verify(value, "wrong")).toBe(false);
  });

  it("rounds= with no $5$/$6$ prefix defaults to $6$", async () => {
    const value = await encryptWithSalt(VECTOR_PASSWORD, "rounds=1300$abcdefgh");
    expect(value.startsWith("$6$rounds=1300$abcdefgh$")).toBe(true);
  });

  it("preserves an explicit rounds= field even at the default count", async () => {
    const value = await encryptWithSalt(VECTOR_PASSWORD, "$5$rounds=5000$abcdefgh");
    expect(value.startsWith("$5$rounds=5000$abcdefgh$")).toBe(true);
    expect(await verify(value, VECTOR_PASSWORD)).toBe(true);
  });

  it("emits no rounds= field when none was specified", async () => {
    const value = await encryptWithSalt(VECTOR_PASSWORD, "$5$abcdefgh");
    expect(value.includes("rounds=")).toBe(false);
  });

  it("accepts a salt at exactly the max length (16 chars)", async () => {
    // Boundary: a 16-character salt is the longest a real device ever
    // writes, and must not be rejected by the length check ('>', not '>=').
    const salt16 = "a".repeat(16);
    const value = await encryptWithSalt(VECTOR_PASSWORD, `$5$${salt16}`);
    expect(value.startsWith(`$5$${salt16}$`)).toBe(true);
    expect(await verify(value, VECTOR_PASSWORD)).toBe(true);
  });
});

describe("juniper encrypted-password: rounds field asymmetry (encrypt canonicalises, verify preserves)", () => {
  // A "rounds=007000$..." field (leading zeros) is accepted by openssl and
  // hashes identically to "rounds=7000$...". The two entry points must
  // deliberately disagree on what they *write*: `encryptWithSalt` is
  // minting a brand new value and must not inherit another tool's
  // formatting quirks (it canonicalises), while `verify` is echoing back
  // what the user pasted and must reproduce it byte for byte to compare
  // correctly (it preserves the raw digits). Mirrors Python's
  // `encrypt`/`check` split on this branch exactly.

  // Real openssl output: `openssl passwd -5/-6 -salt 'rounds=7000$abcdefgh'
  // lab123`. Cross-checking encryptWithSalt's canonicalised output against
  // openssl directly - a third implementation - rules out TS and Python
  // quietly agreeing on the same bug.
  const OPENSSL_CANONICAL_SHA256 =
    "$5$rounds=7000$abcdefgh$kdN5PnJqWO7Kjpjd.tXEYwKq64Z2SoXjgo2SqSFCC87";
  const OPENSSL_CANONICAL_SHA512 =
    "$6$rounds=7000$abcdefgh$sI/ipHpgRHdKDg6kPyRGMV6JVrTreVzWJzNDcNGlIi." +
    "FrxqaOd5hmrrFI20S/gEmON6Tj46C4X/NpaPpRPpkx0";

  it("encryptWithSalt canonicalises a non-canonical rounds= argument ($5$), matching openssl", async () => {
    const value = await encryptWithSalt(VECTOR_PASSWORD, "$5$rounds=007000$abcdefgh");
    expect(value.includes("rounds=007000")).toBe(false);
    expect(value).toBe(OPENSSL_CANONICAL_SHA256);
  });

  it("encryptWithSalt canonicalises a non-canonical rounds= argument ($6$), matching openssl", async () => {
    const value = await encryptWithSalt(VECTOR_PASSWORD, "$6$rounds=007000$abcdefgh");
    expect(value.includes("rounds=007000")).toBe(false);
    expect(value).toBe(OPENSSL_CANONICAL_SHA512);
  });

  // A literal string, never built via encryptWithSalt: if encryptWithSalt's
  // canonicalisation were broken, this test must not be able to agree with
  // itself. Its digest is cross-checked against `openssl passwd -6 -salt
  // 'rounds=007000$abcdefgh' lab123`, which is identical to
  // OPENSSL_CANONICAL_SHA512's digest above - non-canonical digits parse to
  // the same numeric round count, only the display differs. Ported from
  // tests/test_juniper_encrypted_password.py's _NON_CANONICAL_ROUNDS_VECTOR.
  const NON_CANONICAL_ROUNDS_VECTOR =
    "$6$rounds=007000$abcdefgh$sI/ipHpgRHdKDg6kPyRGMV6JVrTreVzWJzNDcNGlIi." +
    "FrxqaOd5hmrrFI20S/gEmON6Tj46C4X/NpaPpRPpkx0";

  it("verify preserves the given rounds= digits verbatim, leading zeros and all", async () => {
    expect(await verify(NON_CANONICAL_ROUNDS_VECTOR, VECTOR_PASSWORD)).toBe(true);
  });

  it("verify rejects a wrong password against the non-canonical-rounds vector", async () => {
    expect(await verify(NON_CANONICAL_ROUNDS_VECTOR, "wrong")).toBe(false);
  });
});

describe("juniper encrypted-password: marker and quote stripping", () => {
  // A single low-rounds reference value, computed once, shared by every
  // stripping variant below - the decoration logic is orthogonal to the
  // round count, and reusing DEFAULT_ROUNDS(5000) here for every variant
  // would be five times the cost for no extra coverage.
  let decoratedVector: string;
  beforeAll(async () => {
    decoratedVector = await encryptWithSalt(VECTOR_PASSWORD, "$5$rounds=1000$abcdefgh");
  });

  it("strips a trailing SECRET-DATA marker", async () => {
    const value = `${decoratedVector} ${SECRET_DATA_MARKER}`;
    expect(await verify(value, VECTOR_PASSWORD)).toBe(true);
  });

  it("strips surrounding double quotes", async () => {
    const value = `"${decoratedVector}"`;
    expect(await verify(value, VECTOR_PASSWORD)).toBe(true);
  });

  it("strips surrounding single quotes", async () => {
    const value = `'${decoratedVector}'`;
    expect(await verify(value, VECTOR_PASSWORD)).toBe(true);
  });

  it("strips a trailing semicolon", async () => {
    const value = `${decoratedVector};`;
    expect(await verify(value, VECTOR_PASSWORD)).toBe(true);
  });

  it("accepts a full pasted config line: quotes, semicolon and marker together", async () => {
    // As pasted from `show configuration system login user ... | display set`,
    // minus the leading keyword.
    const value = `"${decoratedVector}"; ${SECRET_DATA_MARKER}`;
    expect(await verify(value, VECTOR_PASSWORD)).toBe(true);
  });

  it("strips surrounding whitespace", async () => {
    const value = `   ${decoratedVector}   `;
    expect(await verify(value, VECTOR_PASSWORD)).toBe(true);
  });
});

describe("juniper encrypted-password: $1$ (md5crypt) is explicitly out of scope", () => {
  it("verify rejects it by name", async () => {
    await expect(verify("$1$abcdefgh$somehash", VECTOR_PASSWORD)).rejects.toThrow(/\$1\$/);
  });

  it("encryptWithSalt rejects a $1$ salt argument by name", async () => {
    await expect(encryptWithSalt(VECTOR_PASSWORD, "$1$abcdefgh")).rejects.toThrow(/\$1\$/);
  });
});

describe("juniper encrypted-password: decode always throws", () => {
  it("is marked one-way and its decode throws", () => {
    expect(juniperEncryptedPassword.oneWay).toBe(true);
  });

  it("throws for a real vector", async () => {
    await expect(decode()).rejects.toThrow(/one-way/);
  });
});

describe("juniper encrypted-password: out-of-range and malformed rounds", () => {
  it("rejects rounds below the minimum", async () => {
    const value = `$5$rounds=${MIN_ROUNDS - 1}$abcdefgh$` + "a".repeat(43);
    await expect(verify(value, VECTOR_PASSWORD)).rejects.toThrow(
      new RegExp(`${MIN_ROUNDS}-${MAX_ROUNDS}`),
    );
  });

  it("rejects rounds above the maximum", async () => {
    const value = `$5$rounds=${MAX_ROUNDS + 1}$abcdefgh$` + "a".repeat(43);
    await expect(verify(value, VECTOR_PASSWORD)).rejects.toThrow(
      new RegExp(`${MIN_ROUNDS}-${MAX_ROUNDS}`),
    );
  });

  it("rejects a huge (but spec-legal) rounds value in well under a second", async () => {
    // rounds=999999999 is within Drepper's own spec range, and even
    // `openssl passwd` hangs computing it. If a refactor ever moved the
    // bounds check after the hashing, this test would hang instead of
    // failing fast, so the timing assertion is the point, not just
    // rejects.toThrow.
    const value = "$6$rounds=999999999$abcdefgh$" + "a".repeat(86);
    const started = performance.now();
    await expect(verify(value, VECTOR_PASSWORD)).rejects.toThrow(
      new RegExp(`${MIN_ROUNDS}-${MAX_ROUNDS}`),
    );
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it("rejects non-numeric rounds", async () => {
    const value = "$5$rounds=abc$abcdefgh$" + "a".repeat(43);
    await expect(verify(value, VECTOR_PASSWORD)).rejects.toThrow(/Invalid rounds value/);
  });

  it("rejects an empty rounds field", async () => {
    const value = "$5$rounds=$abcdefgh$" + "a".repeat(43);
    await expect(verify(value, VECTOR_PASSWORD)).rejects.toThrow(/Invalid rounds value/);
  });

  it("rejects a rounds field with no separator", async () => {
    const value = "$5$rounds=5000"; // no '$' after the rounds number at all
    await expect(verify(value, VECTOR_PASSWORD)).rejects.toThrow(/Malformed rounds field/);
  });

  it("encryptWithSalt rejects out-of-range rounds too", async () => {
    await expect(
      encryptWithSalt(VECTOR_PASSWORD, "rounds=999999999$abcdefgh"),
    ).rejects.toThrow(new RegExp(`${MIN_ROUNDS}-${MAX_ROUNDS}`));
  });
});

describe("juniper encrypted-password: malformed salt", () => {
  it.each([
    "$5$$" + "a".repeat(43), // empty salt field
    "$5$" + "a".repeat(17) + "$" + "a".repeat(43), // salt too long (17 chars)
    "$5$abc def$" + "a".repeat(43), // space is not in the crypt alphabet
    "$5$ab+cd$" + "a".repeat(43), // '+' is not in the crypt alphabet
  ])("verify rejects malformed salt %#", async (value) => {
    await expect(verify(value, VECTOR_PASSWORD)).rejects.toThrow();
  });

  it.each(["", "a".repeat(17), "abc def", "$1$abcdefgh"])(
    "encryptWithSalt rejects malformed salt argument %j",
    async (badSalt) => {
      await expect(encryptWithSalt(VECTOR_PASSWORD, badSalt)).rejects.toThrow();
    },
  );
});

describe("juniper encrypted-password: empty and malformed values", () => {
  it("rejects an empty value", async () => {
    await expect(verify("", VECTOR_PASSWORD)).rejects.toThrow();
  });

  it("rejects a value with no recognised prefix", async () => {
    await expect(verify("not-a-crypt-value", VECTOR_PASSWORD)).rejects.toThrow(
      /\$5\$.*\$6\$/,
    );
  });

  it("rejects a value missing the hash field", async () => {
    await expect(verify("$5$abcdefgh", VECTOR_PASSWORD)).rejects.toThrow(/Malformed value/);
  });

  it("rejects a hash field of the wrong length", async () => {
    await expect(verify("$5$abcdefgh$tooshort", VECTOR_PASSWORD)).rejects.toThrow(
      /Malformed hash field/,
    );
  });

  it("rejects a hash field with invalid characters", async () => {
    const value = "$5$abcdefgh$" + "!".repeat(43);
    await expect(verify(value, VECTOR_PASSWORD)).rejects.toThrow();
  });
});
