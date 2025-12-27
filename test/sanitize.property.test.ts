import { describe, expect, test } from "vitest";
import fc from "fast-check";
import { sanitize } from "../src/index.js";

const SAFE_TAGS = ["a", "p", "div", "span", "style", "script", "ul", "li", "section"] as const;
const TEXT_TOKENS = ["alpha", "bravo", "charlie", "delta"] as const;

function bodyFrom(html: string): HTMLElement {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");
  return doc.body;
}

const attrPairArb = fc.tuple(
  fc.constantFrom("href", "title", "class", "id", "onclick", "rel", "target", "data-note"),
  fc.oneof(
    fc.constantFrom(
      "https://example.com",
      "javascript:alert(1)",
      " java\nscript:alert(1)",
      "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
      "ok"
    ),
    fc.string({ minLength: 0, maxLength: 12 })
  )
);

const htmlNodeArb: fc.Arbitrary<string> = fc.letrec((tie) => ({
  text: fc.constantFrom(...TEXT_TOKENS),
  element: fc.record({
    tag: fc.constantFrom(...SAFE_TAGS),
    attrs: fc.array(attrPairArb, { maxLength: 3 }),
    children: fc.array(tie("node"), { maxLength: 5 })
  }).map(({ tag, attrs, children }) => {
    const attrsText = attrs
      .map(([name, value]) => ` ${name}="${String(value).replace(/"/g, "&quot;")}"`)
      .join("");
    const childrenText = children.join("");
    return `<${tag}${attrsText}>${childrenText}</${tag}>`;
  }),
  node: fc.oneof(tie("text"), tie("element"))
})).node;

const htmlDocArb = fc.array(htmlNodeArb, { minLength: 1, maxLength: 8 }).map((nodes) => nodes.join(""));

const rulesArb = fc.array(
  fc.oneof(
    fc.constantFrom("a", "p", "div", "span", "style", "script", "ul", "li", "section"),
    fc.constantFrom(
      "a|href",
      "a|title",
      "a|class",
      "a|id",
      "a|onclick",
      "a|rel",
      "a|target",
      "p|class",
      "div|id",
      "section|class",
      "ul|class",
      "li|class"
    ),
    fc.constantFrom(
      "style|.header|margin",
      "style|div|color",
      "style|span|display",
      "style|.footer|padding",
      "style|section|background-color"
    )
  ),
  { minLength: 1, maxLength: 6 }
);

const configArb = fc.record({
  allowCommonAttributes: fc.boolean(),
  allowJavaScript: fc.constant(false),
  maxPasses: fc.integer({ min: 1, max: 6 })
});

const propertyOptions = { seed: 42, numRuns: 250 };

describe("sanitize property-based", () => {
  test("idempotence: sanitize(sanitize(x)) === sanitize(x)", () => {
    fc.assert(
      fc.property(htmlDocArb, rulesArb, configArb, (html, rules, config) => {
        const once = sanitize(html, rules, config);
        const twice = sanitize(once, rules, config);
        expect(twice).toBe(once);
      }),
      propertyOptions
    );
  });

  test("tag counts never exceed rule allowance", () => {
    fc.assert(
      fc.property(htmlDocArb, rulesArb, configArb, (html, rules, config) => {
        const output = sanitize(html, rules, config);
        const body = bodyFrom(output);
        for (const tag of SAFE_TAGS) {
          const allowed = rules.filter((rule) => rule.toLowerCase() === tag).length;
          if (allowed === 0) {
            expect(body.querySelectorAll(tag).length).toBe(0);
          } else {
            expect(body.querySelectorAll(tag).length).toBeLessThanOrEqual(allowed);
          }
        }
      }),
      propertyOptions
    );
  });

  test("attributes respect allowlist and JS safety", () => {
    fc.assert(
      fc.property(htmlDocArb, rulesArb, configArb, (html, rules, config) => {
        const output = sanitize(html, rules, config);
        const body = bodyFrom(output);
        for (const element of Array.from(body.querySelectorAll("*"))) {
          const tag = element.tagName.toLowerCase();
          const allowedAttrs = new Set<string>();

          for (const rule of rules) {
            const parts = rule.split("|").map((p) => p.trim().toLowerCase());
            if (parts.length === 2 && parts[0] === tag) {
              allowedAttrs.add(parts[1]);
            }
          }

          if (config.allowCommonAttributes) {
            for (const attr of ["class", "id"]) {
              allowedAttrs.add(attr);
            }
            if (tag === "a") {
              for (const attr of ["href", "title", "target", "rel"]) {
                allowedAttrs.add(attr);
              }
            }
            if (tag === "img") {
              for (const attr of ["src", "alt", "title", "width", "height"]) {
                allowedAttrs.add(attr);
              }
            }
            if (tag === "html") {
              allowedAttrs.add("lang");
            }
          }

          for (const attr of Array.from(element.attributes)) {
            const name = attr.name.toLowerCase();
            expect(name.startsWith("on")).toBe(false);
            expect(allowedAttrs.has(name)).toBe(true);
            if (name === "href" || name === "src") {
              const normalized = attr.value.replace(/[\u0000-\u001F\u007F\s]+/g, "").toLowerCase();
              expect(normalized.startsWith("javascript:")).toBe(false);
              expect(normalized.startsWith("data:")).toBe(false);
            }
          }
        }
      }),
      propertyOptions
    );
  });

  test("style allowlist leaves only permitted selector/property pairs", () => {
    fc.assert(
      fc.property(htmlDocArb, rulesArb, configArb, (html, rules, config) => {
        const output = sanitize(html, rules, config);
        const body = bodyFrom(output);
        const styleRules = rules
          .map((rule) => rule.split("|").map((p) => p.trim()))
          .filter((parts) => parts.length === 3 && parts[0].toLowerCase() === "style")
          .map((parts) => ({ selector: parts[1], prop: parts[2].toLowerCase() }));
        const allowedSelectors = new Set(styleRules.map((r) => r.selector));

        const styleNodes = Array.from(body.querySelectorAll("style"));
        if (styleRules.length === 0) {
          expect(styleNodes.length).toBe(0);
          return;
        }

        for (const style of styleNodes) {
          const css = style.textContent ?? "";
          for (const block of css.split("}")) {
            const [selectorText, declsText] = block.split("{");
            if (!selectorText || !declsText) continue;
            const selector = selectorText.trim();
            expect(allowedSelectors.has(selector)).toBe(true);
            const allowedProps = styleRules
              .filter((r) => r.selector === selector)
              .map((r) => r.prop);
            for (const decl of declsText.split(";")) {
              const [prop] = decl.split(":");
              if (!prop) continue;
              expect(allowedProps.includes(prop.trim().toLowerCase())).toBe(true);
            }
          }
        }
      }),
      propertyOptions
    );
  });
});
