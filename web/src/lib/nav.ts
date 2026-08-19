/**
 * Group the catalogue by vendor for the navigation bar.
 *
 * The bar lists one menu per vendor rather than one tab per format: with
 * eleven entries a flat row no longer fits. Groups and the entries inside
 * them keep catalogue order, so the registry stays the single place that
 * decides what appears and in what sequence.
 */

import type { CatalogueEntry } from "./ciphers/types";

export interface VendorGroup {
  vendor: string;
  entries: CatalogueEntry[];
}

export function vendorGroups(entries: CatalogueEntry[]): VendorGroup[] {
  const groups: VendorGroup[] = [];
  for (const entry of entries) {
    const existing = groups.find((g) => g.vendor === entry.vendor);
    if (existing) existing.entries.push(entry);
    else groups.push({ vendor: entry.vendor, entries: [entry] });
  }
  return groups;
}

/**
 * The vendor nav button's click handler: open the clicked vendor's menu, or
 * close it if it was already open. Pulled out of `Header.svelte` so the
 * toggle rule itself - independent of *when* a click fires relative to hover
 * or focus - has a unit test. It does not, and cannot, pin the browser event
 * ordering (mouseenter -> mousedown -> focus -> click) that caused the race
 * this function's extraction fixed; that needs a real pointer/DOM
 * environment this project's test setup does not have.
 */
export function toggleVendor(current: string | null, vendor: string): string | null {
  return current === vendor ? null : vendor;
}
