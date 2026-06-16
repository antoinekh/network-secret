import { describe, expect, it } from "vitest";
import { decode, encode } from "./juniper8";

// Master password and $8$ values captured from a real JUNOS 23.2 device.
const MASTER = "a3f8d9e112c04b7af1c3e8b92d057a4e";

const KNOWN: Array<[string, string]> = [
  [
    "$8$aes256-gcm$hmac-sha2-256$100$p8XEvHtxRNE$d/hqRmh5etkBzo7WSdtvjg$7w1eMTYXkz4RdzMF9CAkJQ$qVLunbFwBWwyxln2Vg",
    "LabBgpSecret1",
  ],
  [
    "$8$aes256-gcm$hmac-sha2-256$100$32kBriS21/k$0O08cy0znzu4nrcHxbhMmA$PP0OeY9ANX2UDT1FTDVpiQ$gTrzX/ZppBbu42TpRtw",
    "LabIsisSecret1",
  ],
];

const ROUNDTRIP = ["a", "hello", "LabBgpSecret1", "p@ssw0rd!#", "café", ""];

describe("juniper8", () => {
  it.each(KNOWN)("decodes known device vector", async (encoded, expected) => {
    expect(await decode(encoded, MASTER)).toBe(expected);
  });

  it.each(ROUNDTRIP)("round-trips %j", async (plaintext) => {
    expect(await decode(await encode(plaintext, MASTER), MASTER)).toBe(plaintext);
  });

  it("ignores surrounding whitespace", async () => {
    expect(await decode(`\n  ${KNOWN[0][0]}  \n`, MASTER)).toBe("LabBgpSecret1");
  });

  it("encode output starts with $8$ and has 7 fields", async () => {
    const value = await encode("secret", MASTER);
    expect(value.startsWith("$8$")).toBe(true);
    expect(value.split("$").length).toBe(9);
  });

  it("encode is non-deterministic", async () => {
    const a = await encode("secret", MASTER);
    const b = await encode("secret", MASTER);
    expect(a).not.toBe(b);
    expect(await decode(a, MASTER)).toBe(await decode(b, MASTER));
  });

  it("rejects a wrong master password", async () => {
    await expect(decode(KNOWN[0][0], "wrong-master")).rejects.toThrow(
      /Authentication failed/,
    );
  });

  it("requires a master password", async () => {
    await expect(decode(KNOWN[0][0])).rejects.toThrow(/master password/);
    await expect(encode("x")).rejects.toThrow(/master password/);
  });

  it("rejects a missing magic prefix", async () => {
    await expect(decode("nope", MASTER)).rejects.toThrow(/\$8\$/);
  });

  it("rejects a malformed value", async () => {
    await expect(
      decode("$8$aes256-gcm$hmac-sha2-256$100$short", MASTER),
    ).rejects.toThrow(/Malformed/);
  });

  it("rejects an unsupported algorithm", async () => {
    await expect(
      decode("$8$aes128-gcm$hmac-sha2-256$100$a$b$c$d", MASTER),
    ).rejects.toThrow(/crypt-algo/);
  });
});
