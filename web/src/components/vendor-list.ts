// Joins vendor names into the hero sentence's "Secrets for X, Y and Z" list.
// Extracted out of Home.svelte so the zero/one/many cases can be unit tested.
export function formatVendorList(vendors: string[]): string {
  if (vendors.length === 0) return "network devices";
  if (vendors.length === 1) return vendors[0];
  return `${vendors.slice(0, -1).join(", ")} and ${vendors[vendors.length - 1]}`;
}
