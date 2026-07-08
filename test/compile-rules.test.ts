import { describe, expect, test } from "vitest";
import { RuleSyntaxError, compileRules, sanitize, sanitizeWithPolicy } from "../src/index.js";

describe("compileRules validation", () => {
  test("accepts well-formed rules", () => {
    expect(() =>
      compileRules([
        "p",
        "a",
        "a|href",
        "a|xlink:href",
        "img|data-note",
        "style|.header|margin",
        "style|*|color",
        "style|div|background-color",
        "IMG|SRC",
        " p ",
        "STYLE|.Header|Margin"
      ])
    ).not.toThrow();
  });

  test("rejects empty and whitespace-only rules", () => {
    expect(() => compileRules([""])).toThrow(RuleSyntaxError);
    expect(() => compileRules(["   "])).toThrow(RuleSyntaxError);
  });

  test("rejects rules with empty segments", () => {
    expect(() => compileRules(["a|"])).toThrow(RuleSyntaxError);
    expect(() => compileRules(["|href"])).toThrow(RuleSyntaxError);
    expect(() => compileRules(["style||margin"])).toThrow(RuleSyntaxError);
    expect(() => compileRules(["style|.header|"])).toThrow(RuleSyntaxError);
  });

  test("rejects three-segment rules that do not start with style", () => {
    expect(() => compileRules(["a|href|https"])).toThrow(RuleSyntaxError);
    expect(() => compileRules(["styl|.header|margin"])).toThrow(RuleSyntaxError);
  });

  test("rejects rules with more than three segments", () => {
    expect(() => compileRules(["style|.header|margin|0"])).toThrow(RuleSyntaxError);
  });

  test("rejects whitespace inside tag and attribute names", () => {
    expect(() => compileRules(["di v"])).toThrow(RuleSyntaxError);
    expect(() => compileRules(["a|hr ef"])).toThrow(RuleSyntaxError);
  });

  test("error names the offending rule", () => {
    expect(() => compileRules(["p", "styl|.header|margin"])).toThrow(/styl\|\.header\|margin/);
  });

  test("sanitize propagates rule errors", () => {
    expect(() => sanitize("<p>ok</p>", ["p", "a|"])).toThrow(RuleSyntaxError);
  });

  test("RuleSyntaxError is an Error and exposes the rule", () => {
    try {
      compileRules(["a|"]);
      expect.unreachable("compileRules should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(RuleSyntaxError);
      expect((error as RuleSyntaxError).rule).toBe("a|");
    }
  });
});

describe("CompiledPolicy opacity", () => {
  test("sanitizeWithPolicy rejects objects that did not come from compileRules", () => {
    expect(() => sanitizeWithPolicy("<p>ok</p>", {} as never)).toThrow(TypeError);
    expect(() => sanitizeWithPolicy("<p>ok</p>", null as never)).toThrow(TypeError);
    expect(() =>
      sanitizeWithPolicy("<p>ok</p>", { tagCounts: {}, attrAllowlist: {}, styleAllowlist: {}, config: {} } as never)
    ).toThrow(TypeError);
  });

  test("policies from compileRules keep working", () => {
    const policy = compileRules(["p", "a", "a|href"], { allowCommonAttributes: true });
    const output = sanitizeWithPolicy("<p><a href=\"https://example.com\">ok</a></p>", policy);
    expect(output).toContain("<a href=\"https://example.com\">ok</a>");
  });
});
