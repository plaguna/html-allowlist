import { describe, expect, test } from "vitest";
import { Window } from "happy-dom";
import { compileRules, createSanitizer, sanitize, sanitizeWithPolicy } from "../src/index.js";
import type { SanitizerWindow } from "../src/index.js";

// The bring-your-own-DOM entry: `createSanitizer(window)` binds the sanitizer
// to a DOM the caller supplies, instead of the Node entry's bundled happy-dom
// fallback. Here we build the window explicitly with `new Window()` -- exactly
// what a consumer would do with a jsdom `window` or a linkedom window -- and
// confirm it behaves as a true drop-in for the default `sanitize`.
//
// The point of the feature is decoupling: a consumer who does not want to
// depend on `happy-dom` can pass their own DOM and never touch the fallback
// loader. We stand in for that third-party DOM with a caller-constructed
// happy-dom Window so the test needs no extra dependency.
function makeUserWindow(): SanitizerWindow {
  return new Window() as unknown as SanitizerWindow;
}

const CASES: Array<{ name: string; html: string; rules: string[]; config?: Parameters<typeof sanitize>[2] }> = [
  {
    name: "basic allowlist with attributes",
    html: "<p><a href=\"https://example.com\">ok</a><a>nope</a></p>",
    rules: ["p", "a", "a|href"],
    config: { allowCommonAttributes: true }
  },
  {
    name: "strips a script and event handler",
    html: "<div><script>alert(1)</script><img src=x onerror=alert(1)>text</div>",
    rules: ["div", "img", "img|src"],
    config: { allowCommonAttributes: true }
  },
  {
    name: "javascript: URL is removed",
    html: "<a href=\"javascript:alert(1)\">x</a>",
    rules: ["a", "a|href"]
  },
  {
    name: "document output format",
    html: "<p>hi</p>",
    rules: ["p"],
    config: { outputFormat: "document" }
  }
];

describe("createSanitizer (bring your own DOM)", () => {
  test("is exported from the package root", () => {
    expect(typeof createSanitizer).toBe("function");
  });

  for (const { name, html, rules, config } of CASES) {
    test(`matches the default sanitize output: ${name}`, () => {
      const userWindow = makeUserWindow();
      const byo = createSanitizer(userWindow);
      const expected = sanitize(html, rules, config);
      expect(byo.sanitize(html, rules, config)).toBe(expected);
    });
  }

  test("sanitizeWithPolicy works with a precompiled policy on a supplied window", () => {
    const byo = createSanitizer(makeUserWindow());
    const policy = compileRules(["p", "a", "a|href"], { allowCommonAttributes: true });
    const html = "<p><a href=\"https://example.com\">ok</a></p>";
    expect(byo.sanitizeWithPolicy(html, policy)).toBe(sanitizeWithPolicy(html, policy));
  });

  test("two sanitizers on independent windows do not interfere", () => {
    const a = createSanitizer(makeUserWindow());
    const b = createSanitizer(makeUserWindow());
    const html = "<p><b>x</b></p>";
    expect(a.sanitize(html, ["p"])).toBe(b.sanitize(html, ["p"]));
  });
});
