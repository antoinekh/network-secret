import { describe, expect, it } from "vitest";
import { ciscoType6 } from "./cisco-type6";

const VECTOR = "NdUI^_YP[VEPG[MT_bfTEFNZYFCYe\\R\\M";
const DEVICE_VALUE = "fe_a`iJYE\\DZYJhDhTP[`MYaTgRH_MAAB";

describe("cisco type 6", () => {
  it("decrypts Cisco's own vector", async () => {
    expect(await ciscoType6.decode(VECTOR, "cisco123")).toBe("password");
  });

  it("decrypts a value taken from a real device", async () => {
    expect(await ciscoType6.decode(DEVICE_VALUE, "Cisco123")).toBe("Cisco123");
  });

  it("round-trips, including across the 16-byte block boundary", async () => {
    for (const plain of ["", "a", "x".repeat(16), "x".repeat(17), "clé-secrète"]) {
      const encoded = await ciscoType6.encode(plain, "MyMaster");
      expect(await ciscoType6.decode(encoded, "MyMaster")).toBe(plain);
    }
  });

  it("is non-deterministic", async () => {
    const a = await ciscoType6.encode("secret", "MyMaster");
    const b = await ciscoType6.encode("secret", "MyMaster");
    expect(a).not.toBe(b);
  });

  it("rejects the wrong master key", async () => {
    await expect(ciscoType6.decode(VECTOR, "wrong")).rejects.toThrow(
      /Authentication failed/,
    );
  });

  it("rejects a malformed value", async () => {
    await expect(ciscoType6.decode("AAAA", "cisco123")).rejects.toThrow();
  });

  it("round-trips a plaintext ending in NUL", async () => {
    const encoded = await ciscoType6.encode("x\x00", "MyMaster");
    expect(await ciscoType6.decode(encoded, "MyMaster")).toBe("x\x00");
  });

  it("round-trips a plaintext that is a single NUL", async () => {
    const encoded = await ciscoType6.encode("\x00", "MyMaster");
    expect(await ciscoType6.decode(encoded, "MyMaster")).toBe("\x00");
  });

  it("round-trips a plaintext with an interior NUL", async () => {
    const encoded = await ciscoType6.encode("a\x00b", "MyMaster");
    expect(await ciscoType6.decode(encoded, "MyMaster")).toBe("a\x00b");
  });

  it("accepts the longest valid plaintext", async () => {
    // 4095 bytes plus the NUL terminator is exactly 256 blocks, the most the
    // one-byte keystream counter can address.
    const plain = "x".repeat(4095);
    const encoded = await ciscoType6.encode(plain, "MyMaster");
    expect(await ciscoType6.decode(encoded, "MyMaster")).toBe(plain);
  });

  it("rejects a plaintext one byte over the limit", async () => {
    await expect(
      ciscoType6.encode("x".repeat(4096), "MyMaster"),
    ).rejects.toThrow(/too long/);
  });

  it("measures the limit in UTF-8 bytes, not characters", async () => {
    // 2048 two-byte characters is 4096 encoded bytes, one over the limit,
    // even though .length reports only 2048.
    const plain = "é".repeat(2048);
    await expect(ciscoType6.encode(plain, "MyMaster")).rejects.toThrow(
      /too long/,
    );
  });
});
