/**
 * Minimal base64 helpers (standard RFC 4648 alphabet, padding optional).
 *
 * Works in the browser and in Node (both expose `btoa`/`atob` globally),
 * so the same code is exercised by the Vitest suite and at runtime.
 */

export function bytesToBase64(bytes: Uint8Array, pad = false): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binary);
  return pad ? b64 : b64.replace(/=+$/, "");
}

export function base64ToBytes(text: string): Uint8Array {
  const padding = text.length % 4 === 0 ? "" : "=".repeat(4 - (text.length % 4));
  let binary: string;
  try {
    binary = atob(text + padding);
  } catch {
    throw new Error(`Invalid base64: '${text}'`);
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}
