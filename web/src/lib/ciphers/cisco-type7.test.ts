import { describe, expect, it } from "vitest";
import { ciscoType7 } from "./cisco-type7";

describe("cisco type 7", () => {
  it("decodes the known vector", async () => {
    expect(await ciscoType7.decode("060506324F41")).toBe("cisco");
  });

  it("round-trips", async () => {
    const encoded = await ciscoType7.encode("L@bS3cr3t!");
    expect(await ciscoType7.decode(encoded)).toBe("L@bS3cr3t!");
  });

  it("uses a seed IOS would emit", async () => {
    for (let i = 0; i < 30; i++) {
      const seed = Number((await ciscoType7.encode("x")).slice(0, 2));
      expect(seed).toBeGreaterThanOrEqual(0);
      expect(seed).toBeLessThanOrEqual(15);
    }
  });

  it.each(["", "0", "AB1234", "060506324F4", "06ZZ", "530506324F41"])(
    "rejects %j",
    async (value) => {
      await expect(ciscoType7.decode(value)).rejects.toThrow();
    },
  );

  it("rejects a non-Latin-1 plaintext", async () => {
    await expect(ciscoType7.encode("secret€")).rejects.toThrow();
  });
});
