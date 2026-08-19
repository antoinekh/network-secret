import { describe, expect, it, vi } from "vitest";
import { catalogue } from "../lib/ciphers/registry";

// Importing the catalogue pulls in the explainer components, which use the
// `link` action from `../lib/router`. That module reads `window.location` at
// import time, which doesn't exist in vitest's node environment. Stub it out;
// this test only cares about the catalogue's data, never navigation. vi.mock
// calls are hoisted above imports, so this applies before the import above
// resolves the router module transitively.
vi.mock("../lib/router", () => ({
  path: { subscribe: () => () => {} },
  navigate: () => {},
  link: () => ({ destroy() {} }),
}));

describe("catalogue badges", () => {
  it("gives every available converter a property badge", () => {
    for (const entry of catalogue) {
      if (entry.kind !== "converter" || entry.status !== "available") continue;
      expect(
        entry.oneWay === true || entry.reversible === true || entry.keyed === true,
        `${entry.id} would render with no property badge`,
      ).toBe(true);
    }
  });

  it("names every vendor in the catalogue exactly once", () => {
    const vendors = [...new Set(catalogue.map((c) => c.vendor))];
    expect(vendors).toEqual(["Juniper/HPE", "Nokia SR OS", "Cisco IOS"]);
    expect(new Set(vendors).size).toBe(vendors.length);
  });
});
