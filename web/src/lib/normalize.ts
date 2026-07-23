/**
 * Normalize a value pasted from a device config.
 *
 * Config lines wrap secrets in quotes, e.g. `authentication-key "$9$abc"` or
 * `key "a3f8…"`. Users often copy the quoted token, so trim whitespace and
 * strip a single surrounding layer of matching quotes before decoding.
 */
export function unwrapValue(input: string): string {
  const trimmed = input.trim();
  if (
    trimmed.length >= 2 &&
    ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'")))
  ) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}
