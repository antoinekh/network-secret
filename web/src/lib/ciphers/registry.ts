/**
 * The catalogue: every format the site knows about, converters and explainers.
 *
 * - To add a converter: write a module exporting a `Cipher`, import it, and
 *   append it to `ciphers` below.
 * - To add an explainer: add an entry to `../explainers.ts`.
 *
 * Each entry is stamped here with a `kind` and a two-digit `index` derived from
 * its position, so the home card, nav tab, route, page, and title all follow
 * automatically - no component hardcodes a format or its number.
 */

import type { CatalogueEntry, ConverterEntry } from "./types";
import { juniper9 } from "./juniper9";
import { juniper8 } from "./juniper8";
import { nokiaCustomHash } from "./nokia-custom-hash";
import { ciscoType6 } from "./cisco-type6";
import { ciscoType7 } from "./cisco-type7";
import { explainers } from "../explainers";

const ciphers = [juniper9, juniper8, nokiaCustomHash, ciscoType6, ciscoType7];

export const catalogue: CatalogueEntry[] = [
  ...ciphers.map((c) => ({ ...c, kind: "converter" as const })),
  ...explainers.map((e) => ({ ...e, kind: "explainer" as const })),
].map((entry, i) => ({ ...entry, index: String(i + 1).padStart(2, "0") }));

export function findEntry(id: string): CatalogueEntry | undefined {
  return catalogue.find((entry) => entry.id === id);
}

/** True when the entry is an interactive converter (narrows the union). */
export function isConverter(entry: CatalogueEntry): entry is ConverterEntry {
  return entry.kind === "converter";
}
