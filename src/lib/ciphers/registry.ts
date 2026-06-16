/**
 * The catalogue of supported (and planned) formats.
 *
 * To add a format: create a module exporting a `Cipher`, import it here, and
 * append it to `registry`. Everything else (home card, route, page) follows.
 */

import type { Cipher } from "./types";
import { juniper9 } from "./juniper9";
import { juniper8 } from "./juniper8";
import { nokiaCustomHash } from "./nokia-custom-hash";

export const registry: Cipher[] = [juniper9, juniper8, nokiaCustomHash];

export function findCipher(id: string): Cipher | undefined {
  return registry.find((c) => c.id === id);
}
