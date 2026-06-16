import { describe, expect, it } from "vitest";
import { unwrapValue } from "./normalize";

describe("unwrapValue", () => {
  it("strips surrounding double quotes", () => {
    expect(unwrapValue('"$9$FNkC3/t1IcevLuOWx"')).toBe("$9$FNkC3/t1IcevLuOWx");
  });

  it("strips surrounding single quotes", () => {
    expect(unwrapValue("'secret'")).toBe("secret");
  });

  it("trims whitespace, including inside quotes", () => {
    expect(unwrapValue('  "  $8$value  "  ')).toBe("$8$value");
  });

  it("leaves unquoted values untouched (just trimmed)", () => {
    expect(unwrapValue("  $9$abc  ")).toBe("$9$abc");
  });

  it("only strips one matching layer", () => {
    expect(unwrapValue('""')).toBe("");
    expect(unwrapValue('"a"b"')).toBe('a"b');
  });

  it("does not strip a lone quote character", () => {
    expect(unwrapValue('"')).toBe('"');
  });
});
