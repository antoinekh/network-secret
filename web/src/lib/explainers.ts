/**
 * Documentation-only pages for Nokia SR OS formats we deliberately do not
 * decode here. Each entry supplies the header/facts/related metadata; the
 * `component` is the prose body, styled by `ExplainerPage`. Listed in the
 * catalogue by `ciphers/registry.ts`, so cards, nav, routes and titles follow
 * automatically - nothing hardcodes a format.
 */

import type { Explainer } from "./ciphers/types";
import NokiaHash from "../components/explainers/NokiaHash.svelte";
import NokiaHash2 from "../components/explainers/NokiaHash2.svelte";
import NokiaHash3 from "../components/explainers/NokiaHash3.svelte";

export const explainers: Explainer[] = [
  {
    id: "hash",
    name: "Nokia hash",
    vendor: "Nokia SR OS",
    tagline:
      "SR OS's oldest reversible obfuscation - the unsalted ancestor of hash2, and the weakest of the four. Decodable in principle, but only with a key baked into the firmware, so this is an explainer.",
    cardTagline: "SR OS's oldest obfuscation - unsalted, the weakest of the four.",
    badges: [
      { label: "Nokia SR OS" },
      { label: "Reversible" },
      { label: "Not decodable here", tone: "muted" },
    ],
    facts: [
      { term: "Vendor", value: "Nokia SR OS" },
      { term: "Kind", value: "AES-256-CTR obfuscation" },
      { term: "Key", value: "fixed, embedded in SR OS" },
      { term: "Salt", value: "none" },
      { term: "Scope", value: "global (any value)" },
      { term: "Decodable here", value: "No" },
    ],
    related: [
      {
        href: "/hash2",
        label: "Nokia hash2",
        note: "The same construction with a per-leaf salt added.",
      },
      {
        href: "/nokia-custom-hash",
        label: "Nokia custom-hash",
        note: "The portable format you hold the key for - decodable here.",
      },
    ],
    component: NokiaHash,
  },
  {
    id: "hash2",
    name: "Nokia hash2",
    vendor: "Nokia SR OS",
    tagline:
      "SR OS's default reversible obfuscation for configuration secrets. Reversible with a key baked into the software - which is exactly why this is an explainer, not a converter.",
    cardTagline: "SR OS default obfuscation - reversible with a key baked into the firmware.",
    badges: [
      { label: "Nokia SR OS" },
      { label: "Reversible" },
      { label: "Not decodable here", tone: "muted" },
    ],
    facts: [
      { term: "Vendor", value: "Nokia SR OS" },
      { term: "Kind", value: "AES-256-CTR obfuscation" },
      { term: "Key", value: "fixed, embedded in SR OS" },
      { term: "Salt", value: "per config leaf-key" },
      { term: "Scope", value: "leaf-specific (not node)" },
      { term: "Decodable here", value: "No" },
    ],
    related: [
      {
        href: "/nokia-custom-hash",
        label: "Nokia custom-hash",
        note: "The portable format you hold the key for - decodable here.",
      },
      {
        href: "/hash3",
        label: "Nokia hash3",
        note: "The 26.7+ AEAD successor, keyed to a user primary secret.",
      },
    ],
    component: NokiaHash2,
  },
  {
    id: "hash3",
    name: "Nokia hash3",
    vendor: "Nokia SR OS",
    tagline:
      "SR OS 26.7+ primary-secret encryption for configuration secrets. A real authenticated cipher, keyed to one specific router. This is an explainer, not a converter.",
    cardTagline: "SR OS 26.7+ primary-secret encryption - why it can't be decoded here.",
    badges: [
      { label: "Nokia SR OS" },
      { label: "AEAD", tone: "accent" },
      { label: "Not decodable here", tone: "muted" },
    ],
    facts: [
      { term: "Vendor", value: "Nokia SR OS" },
      { term: "Since", value: "26.7+", mono: true },
      { term: "Kind", value: "AES-256-GCM (AEAD)" },
      { term: "Key", value: "PBKDF2-SHA3-512(master, per-leaf salt)" },
      { term: "Salt", value: "per config leaf-key" },
      { term: "Decodable here", value: "No" },
    ],
    related: [
      {
        href: "/nokia-custom-hash",
        label: "Nokia custom-hash",
        note: "The portable, deterministic predecessor you can decode here.",
      },
    ],
    component: NokiaHash3,
  },
];
