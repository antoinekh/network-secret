import { describe, expect, it } from "vitest";
import { ciscoType9 } from "./cisco-type9";

const PASSWORD = "cisco123";
const HASH = "$9$ihSswXDbk0kaVK$o.uyR2nMrWtjMkrQwBXUR5lVuVt/KzG23rmYvshODXI";

describe("cisco type 9", () => {
  it("verifies Cisco's own vector", async () => {
    expect(await ciscoType9.verify!(HASH, PASSWORD)).toBe(true);
  });

  it("rejects the wrong password", async () => {
    expect(await ciscoType9.verify!(HASH, "wrong")).toBe(false);
  });

  it("hashes with a fresh salt each call", async () => {
    const a = await ciscoType9.encode(PASSWORD);
    const b = await ciscoType9.encode(PASSWORD);
    expect(a).not.toBe(b);
    expect(a.startsWith("$9$")).toBe(true);
    expect(a.split("$")[2]).toHaveLength(14);
  });

  it("verifies a hash it produced", async () => {
    const value = await ciscoType9.encode("L@bS3cr3t!");
    expect(await ciscoType9.verify!(value, "L@bS3cr3t!")).toBe(true);
  });

  it("is marked one-way and its decode throws", async () => {
    expect(ciscoType9.oneWay).toBe(true);
    await expect(ciscoType9.decode(HASH)).rejects.toThrow(/one-way/);
  });

  it.each([
    "",
    "nope",
    "$8$J5J/1K3e8gk974$HRezVpnMZOhOU2uxFTv.79S1U1PpMScizwXS3Z1Dx1s",
    "$9$ihSswXDbk0kaVK",
    "$9$has space$abc",
  ])("rejects %j", async (value) => {
    await expect(ciscoType9.verify!(value, PASSWORD)).rejects.toThrow();
  });
});
