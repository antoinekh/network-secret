import { describe, expect, it, vi } from "vitest";
import { catalogue } from "./ciphers/registry";
import { vendorGroups } from "./nav";

// Importing the catalogue pulls in the explainer components, which use the
// `link` action from `./router`. That module reads `window.location` at
// import time, which doesn't exist in vitest's node environment. Stub it out;
// this test only cares about the catalogue's data, never navigation. vi.mock
// calls are hoisted above imports, so this applies before the import above
// resolves the router module transitively.
vi.mock("./router", () => ({
  path: { subscribe: () => () => {} },
  navigate: () => {},
  link: () => ({ destroy() {} }),
}));

describe("vendorGroups", () => {
  it("covers every catalogue entry exactly once", () => {
    const grouped = vendorGroups(catalogue).flatMap((g) => g.entries);
    expect(grouped.map((e) => e.id).sort()).toEqual(
      catalogue.map((e) => e.id).sort(),
    );
  });

  it("keeps catalogue order for the groups and inside them", () => {
    const groups = vendorGroups(catalogue);
    expect(groups.map((g) => g.vendor)).toEqual([
      "Juniper/HPE",
      "Nokia SR OS",
      "Cisco IOS",
    ]);
    expect(groups[0].entries.map((e) => e.id)).toEqual(["juniper9", "juniper8"]);
    expect(groups[1].entries.map((e) => e.id)).toEqual([
      "nokia-custom-hash",
      "hash",
      "hash2",
      "hash3",
    ]);
    expect(groups[2].entries.map((e) => e.id)).toEqual([
      "cisco-type6",
      "cisco-type7",
      "cisco-type8",
      "cisco-type9",
    ]);
  });

  it("puts all four Nokia entries in one group", () => {
    const nokia = vendorGroups(catalogue).find((g) => g.vendor === "Nokia SR OS");
    expect(nokia?.entries).toHaveLength(4);
  });

  it("puts all four Cisco entries in one group", () => {
    const cisco = vendorGroups(catalogue).find((g) => g.vendor === "Cisco IOS");
    expect(cisco?.entries).toHaveLength(4);
  });
});
