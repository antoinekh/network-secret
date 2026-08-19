import { describe, expect, it } from "vitest";
import { ciscoType8 } from "./cisco-type8";

const PASSWORD = "cisco123";
const HASH = "$8$J5J/1K3e8gk974$HRezVpnMZOhOU2uxFTv.79S1U1PpMScizwXS3Z1Dx1s";

describe("cisco type 8", () => {
  it("verifies Cisco's own vector", async () => {
    expect(await ciscoType8.verify!(HASH, PASSWORD)).toBe(true);
  });

  it("rejects the wrong password", async () => {
    expect(await ciscoType8.verify!(HASH, "wrong")).toBe(false);
  });

  it("hashes with a fresh salt each call", async () => {
    const a = await ciscoType8.encode(PASSWORD);
    const b = await ciscoType8.encode(PASSWORD);
    expect(a).not.toBe(b);
    expect(a.startsWith("$8$")).toBe(true);
    expect(a.split("$")[2]).toHaveLength(14);
  });

  it("verifies a hash it produced", async () => {
    const value = await ciscoType8.encode("L@bS3cr3t!");
    expect(await ciscoType8.verify!(value, "L@bS3cr3t!")).toBe(true);
  });

  it("is marked one-way and its decode throws", async () => {
    expect(ciscoType8.oneWay).toBe(true);
    await expect(ciscoType8.decode(HASH)).rejects.toThrow(/one-way/);
  });

  it.each(["", "nope", "$9$abc$def", "$8$J5J/1K3e8gk974", "$8$has space$abc"])(
    "rejects %j",
    async (value) => {
      await expect(ciscoType8.verify!(value, PASSWORD)).rejects.toThrow();
    },
  );
});
