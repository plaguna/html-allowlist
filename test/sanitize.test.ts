import { describe, expect, test } from "vitest";
import { compileRules, sanitize, sanitizeWithPolicy } from "../src/index.js";

function bodyFrom(html: string): HTMLElement {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");
  return doc.body;
}

function firstTag(html: string, tagName: string): Element | null {
  const body = bodyFrom(html);
  return body.querySelector(tagName);
}

describe("sanitize", () => {
  test("enforces tag counts with multiset rules", () => {
    const input = "<p><a>one</a><a>two</a><a>three</a></p>";
    const output = sanitize(input, ["p", "a", "a"]);
    expect(bodyFrom(output).innerHTML).toBe("<p><a>one</a><a>two</a></p>");
  });

  test("applies tag counts globally across the document", () => {
    const input = "<a>first</a><div><a>second</a></div><a>third</a>";
    const output = sanitize(input, ["a", "a", "div"]);
    expect(bodyFrom(output).innerHTML).toBe("<a>first</a><div><a>second</a></div>");
  });

  test("matches tag rules case-insensitively", () => {
    const input = "<a>ok</a>";
    const output = sanitize(input, ["A"]);
    expect(bodyFrom(output).innerHTML).toBe("<a>ok</a>");
  });

  test("returns a full document with html, head, and body", () => {
    const output = sanitize("<p>ok</p>", ["html", "head", "body", "p"]);
    expect(output).toBe("<html><head></head><body><p>ok</p></body></html>");
  });

  test("falls back to happy-dom when DOMParser is not available", () => {
    const original = globalThis.DOMParser;
    (globalThis as { DOMParser?: typeof DOMParser }).DOMParser = undefined;
    try {
      const output = sanitize("<p>ok</p>", ["p"]);
      expect(output).toBe("<html><head></head><body><p>ok</p></body></html>");
    } finally {
      (globalThis as { DOMParser?: typeof DOMParser }).DOMParser = original;
    }
  });

  test("disables happy-dom external resource loading during sanitize", () => {
    const happyDOM = (globalThis as { happyDOM?: { settings?: Record<string, boolean> } }).happyDOM;
    if (!happyDOM?.settings) return;
    happyDOM.settings.disableCSSFileLoading = false;
    happyDOM.settings.disableJavaScriptFileLoading = false;
    happyDOM.settings.disableIframePageLoading = false;
    happyDOM.settings.handleDisabledFileLoadingAsSuccess = false;
    sanitize("<link rel=\"stylesheet\" href=\"https://example.com/a.css\">", ["html", "head", "body", "link"]);
    expect(happyDOM.settings.disableCSSFileLoading).toBe(true);
    expect(happyDOM.settings.disableJavaScriptFileLoading).toBe(true);
    expect(happyDOM.settings.disableIframePageLoading).toBe(true);
    expect(happyDOM.settings.handleDisabledFileLoadingAsSuccess).toBe(true);
  });

  test("allows only explicitly permitted attributes", () => {
    const input = "<a href=\"https://example.com\" title=\"nope\">link</a>";
    const output = sanitize(input, ["a", "a|href"]);
    const anchor = firstTag(output, "a");
    expect(anchor?.getAttribute("href")).toBe("https://example.com");
    expect(anchor?.hasAttribute("title")).toBe(false);
  });

  test("allowCommonAttributes permits conservative defaults without bypassing tag rules", () => {
    const input = "<a href=\"https://example.com\" title=\"ok\" rel=\"nofollow\" target=\"_blank\">x</a>";
    const output = sanitize(input, ["a"], { allowCommonAttributes: true });
    const anchor = firstTag(output, "a");
    expect(anchor?.getAttribute("href")).toBe("https://example.com");
    expect(anchor?.getAttribute("title")).toBe("ok");
    expect(anchor?.getAttribute("rel")).toBe("nofollow");
    expect(anchor?.getAttribute("target")).toBe("_blank");

    const removed = sanitize(input, [], { allowCommonAttributes: true });
    expect(firstTag(removed, "a")).toBe(null);
  });

  test("removes style tags when not allowed", () => {
    const input = "<style>.header{margin:0}</style><p>ok</p>";
    const output = sanitize(input, ["p"]);
    expect(firstTag(output, "style")).toBe(null);
    expect(bodyFrom(output).innerHTML).toBe("<p>ok</p>");
  });

  test("filters style declarations by selector and property", () => {
    const input = "<style>.header{margin:0;padding:2px}.footer{margin:1px}</style>";
    const output = sanitize(input, ["style", "style|.header|margin"]);
    const style = firstTag(output, "style");
    expect(style).not.toBe(null);
    const css = style?.textContent ?? "";
    expect(css).toContain(".header");
    expect(css).toContain("margin");
    expect(css).not.toContain("padding");
    expect(css).not.toContain(".footer");
  });

  test("drops @import rules even when style tags are allowed", () => {
    const input = "<style>@import url(\"https://example.com/x.css\");.header{margin:0}</style>";
    const output = sanitize(input, ["style", "style|.header|margin"]);
    const style = firstTag(output, "style");
    const css = style?.textContent ?? "";
    expect(css).toContain(".header");
    expect(css).not.toContain("@import");
  });

  test("removes declarations that use url() even when the property is allowed", () => {
    const input = "<style>.header{background-image:url(\"https://example.com/x.png\");margin:0}</style>";
    const output = sanitize(input, ["style", "style|.header|background-image", "style|.header|margin"]);
    const style = firstTag(output, "style");
    const css = style?.textContent ?? "";
    expect(css).toContain(".header");
    expect(css).toContain("margin");
    expect(css).not.toContain("background-image");
    expect(css).not.toContain("url(");
  });

  test("strips event handlers and javascript: URLs when allowJavaScript is false", () => {
    const input = "<a href=\"javascript:alert(1)\" onclick=\"alert(2)\">x</a>";
    const output = sanitize(input, ["a", "a|href"], { allowJavaScript: false });
    const anchor = firstTag(output, "a");
    expect(anchor?.hasAttribute("onclick")).toBe(false);
    expect(anchor?.getAttribute("href") ?? "").not.toMatch(/^javascript:/i);
  });

  test("blocks javascript: URLs hidden by whitespace or control characters", () => {
    const input =
      "<a href=\" java\\nscript:alert(1)\">x</a><a href=\"java\\t\\rscript:alert(2)\">y</a>";
    const output = sanitize(input, ["a", "a", "a|href"], { allowJavaScript: false });
    const anchors = Array.from(bodyFrom(output).querySelectorAll("a"));
    expect(anchors).toHaveLength(2);
    for (const anchor of anchors) {
      const href = anchor.getAttribute("href") ?? "";
      expect(href).not.toMatch(/^\s*javascript:/i);
    }
  });

  test("blocks javascript: URLs with mixed case and HTML entities", () => {
    const input =
      "<a href=\"JaVaScRiPt:alert(1)\">x</a>" +
      "<a href=\"jav&#x61;script:alert(2)\">y</a>";
    const output = sanitize(input, ["a", "a", "a|href"], { allowJavaScript: false });
    const anchors = Array.from(bodyFrom(output).querySelectorAll("a"));
    expect(anchors).toHaveLength(2);
    for (const anchor of anchors) {
      const href = anchor.getAttribute("href") ?? "";
      expect(href).not.toMatch(/^javascript:/i);
    }
  });

  test("strips javascript: and data: URLs from other URL-bearing attributes", () => {
    const input =
      "<form action=\"javascript:alert(1)\"><button formaction=\"data:text/html,evil\">go</button></form>" +
      "<svg><a xlink:href=\"javascript:alert(2)\">x</a></svg>" +
      "<img src=\"https://example.com/ok.png\" " +
      "srcset=\"javascript:alert(1) 1x, https://example.com/ok@2x.png 2x\" " +
      "poster=\"data:text/html,evil\">";
    const rules = [
      "form",
      "form|action",
      "button",
      "button|formaction",
      "svg",
      "a",
      "a|xlink:href",
      "img",
      "img|src",
      "img|srcset",
      "img|poster"
    ];
    const output = sanitize(input, rules, { allowJavaScript: false });
    const body = bodyFrom(output);
    expect(body.querySelector("form")?.hasAttribute("action")).toBe(false);
    expect(body.querySelector("button")?.hasAttribute("formaction")).toBe(false);
    expect(body.querySelector("svg a")?.hasAttribute("xlink:href")).toBe(false);
    expect(body.querySelector("img")?.getAttribute("src")).toBe("https://example.com/ok.png");
    expect(body.querySelector("img")?.hasAttribute("srcset")).toBe(false);
    expect(body.querySelector("img")?.hasAttribute("poster")).toBe(false);
  });

  test("keeps safe values for other URL-bearing attributes", () => {
    const input =
      "<form action=\"/submit\"><button formaction=\"https://example.com/submit\">go</button></form>" +
      "<svg><a xlink:href=\"https://example.com\">x</a></svg>" +
      "<img src=\"https://example.com/ok.png\" " +
      "srcset=\"https://example.com/ok.png 1x, https://example.com/ok@2x.png 2x\" " +
      "poster=\"https://example.com/poster.png\">";
    const rules = [
      "form",
      "form|action",
      "button",
      "button|formaction",
      "svg",
      "a",
      "a|xlink:href",
      "img",
      "img|src",
      "img|srcset",
      "img|poster"
    ];
    const output = sanitize(input, rules, { allowJavaScript: false });
    const body = bodyFrom(output);
    expect(body.querySelector("form")?.getAttribute("action")).toBe("/submit");
    expect(body.querySelector("button")?.getAttribute("formaction")).toBe("https://example.com/submit");
    expect(body.querySelector("svg a")?.getAttribute("xlink:href")).toBe("https://example.com");
    expect(body.querySelector("img")?.getAttribute("src")).toBe("https://example.com/ok.png");
    expect(body.querySelector("img")?.getAttribute("srcset")).toContain("https://example.com/ok.png");
    expect(body.querySelector("img")?.getAttribute("poster")).toBe("https://example.com/poster.png");
  });

  test("survives hostile inputs with obfuscated URLs across tags", () => {
    const input =
      "<div>" +
      "<a href=\" java\\nscript:alert(1)\" title=\"ok\">x</a>" +
      "<form action=\"jav&#x61;script:alert(2)\"><button formaction=\"data:text/html,evil\">go</button></form>" +
      "<svg><a xlink:href=\"java\\tscript:alert(3)\">y</a></svg>" +
      "<img src=\"https://example.com/ok.png\" " +
      "srcset=\"java\\rscript:alert(4) 1x, https://example.com/ok@2x.png 2x\" " +
      "poster=\"data:text/html,evil\">" +
      "</div>";
    const rules = [
      "div",
      "a",
      "a|href",
      "a|title",
      "form",
      "form|action",
      "button",
      "button|formaction",
      "svg",
      "a|xlink:href",
      "img",
      "img|src",
      "img|srcset",
      "img|poster"
    ];
    const output = sanitize(input, rules, { allowJavaScript: false });
    const body = bodyFrom(output);
    for (const element of Array.from(body.querySelectorAll("*"))) {
      for (const attr of Array.from(element.attributes)) {
        const name = attr.name.toLowerCase();
        if (!["href", "src", "xlink:href", "action", "formaction", "poster", "srcset"].includes(name)) {
          continue;
        }
        const normalized = attr.value.replace(/[\u0000-\u001F\u007F\s]+/g, "").toLowerCase();
        expect(normalized.startsWith("javascript:")).toBe(false);
        expect(normalized.startsWith("data:")).toBe(false);
      }
    }
  });

  test("strips dangerous URLs from exotic HTML and SVG elements", () => {
    const input =
      "<head>" +
      "<link rel=\"stylesheet\" href=\"javascript:alert(1)\">" +
      "</head>" +
      "<body>" +
      "<object data=\"data:text/html,evil\"></object>" +
      "<embed src=\"java&#x0A;script:alert(2)\">" +
      "<svg>" +
      "<use href=\"javascript:alert(3)\"></use>" +
      "<image href=\"data:image/svg+xml,<svg></svg>\"></image>" +
      "</svg>" +
      "</body>";
    const rules = [
      "html",
      "head",
      "body",
      "link",
      "link|rel",
      "link|href",
      "object",
      "object|data",
      "embed",
      "embed|src",
      "svg",
      "use",
      "use|href",
      "image",
      "image|href"
    ];
    const output = sanitize(input, rules, { allowJavaScript: false });
    const doc = new DOMParser().parseFromString(output, "text/html");
    const link = doc.querySelector("link");
    const object = doc.querySelector("object");
    const embed = doc.querySelector("embed");
    const use = doc.querySelector("use");
    const image = doc.querySelector("image");
    expect(link?.hasAttribute("href")).toBe(false);
    expect(object?.hasAttribute("data")).toBe(false);
    expect(embed?.hasAttribute("src")).toBe(false);
    expect(use?.hasAttribute("href")).toBe(false);
    expect(image?.hasAttribute("href")).toBe(false);
  });

  test("keeps safe URLs on exotic HTML and SVG elements", () => {
    const input =
      "<head>" +
      "<link rel=\"stylesheet\" href=\"https://example.com/site.css\">" +
      "</head>" +
      "<body>" +
      "<object data=\"https://example.com/file\"></object>" +
      "<embed src=\"https://example.com/plug\">" +
      "<svg>" +
      "<use href=\"https://example.com/icon.svg#id\"></use>" +
      "<image href=\"https://example.com/image.svg\"></image>" +
      "</svg>" +
      "</body>";
    const rules = [
      "html",
      "head",
      "body",
      "link",
      "link|rel",
      "link|href",
      "object",
      "object|data",
      "embed",
      "embed|src",
      "svg",
      "use",
      "use|href",
      "image",
      "image|href"
    ];
    const output = sanitize(input, rules, { allowJavaScript: false });
    const doc = new DOMParser().parseFromString(output, "text/html");
    const link = doc.querySelector("link");
    const object = doc.querySelector("object");
    const embed = doc.querySelector("embed");
    const use = doc.querySelector("use");
    const image = doc.querySelector("image");
    expect(link?.getAttribute("href")).toBe("https://example.com/site.css");
    expect(object?.getAttribute("data")).toBe("https://example.com/file");
    expect(embed?.getAttribute("src")).toBe("https://example.com/plug");
    expect(use?.getAttribute("href")).toBe("https://example.com/icon.svg#id");
    expect(image?.getAttribute("href")).toBe("https://example.com/image.svg");
  });

  test("applies DOMPurify to strip dangerous SVG attributes when allowJavaScript is false", () => {
    const input = "<svg><a xlink:href=\"javascript:alert(1)\">x</a></svg>";
    const rules = ["svg", "a", "a|xlink:href"];
    const output = sanitize(input, rules, { allowJavaScript: false });
    const svg = firstTag(output, "svg");
    const anchor = svg?.querySelector("a");
    expect(anchor?.hasAttribute("xlink:href")).toBe(false);
    expect(output.toLowerCase()).not.toContain("javascript:");
  });

  test("removes event handler attributes even if explicitly allowed when allowJavaScript is false", () => {
    const input = "<a onclick=\"alert(1)\">x</a>";
    const output = sanitize(input, ["a", "a|onclick"], { allowJavaScript: false });
    const anchor = firstTag(output, "a");
    expect(anchor?.hasAttribute("onclick")).toBe(false);
  });

  test("removes script tags when allowJavaScript is false, even if rules include script", () => {
    const input = "<script>alert(1)</script><p>ok</p>";
    const output = sanitize(input, ["script", "p"], { allowJavaScript: false });
    expect(firstTag(output, "script")).toBe(null);
    expect(firstTag(output, "p")?.textContent).toBe("ok");
  });

  test("keeps script tags when allowJavaScript is true and explicitly allowed", () => {
    const input = "<script>alert(1)</script>";
    const output = sanitize(input, ["script"], { allowJavaScript: true });
    expect(firstTag(output, "script")?.textContent).toBe("alert(1)");
  });

  test("strips disallowed SVG attributes even when allowJavaScript is true", () => {
    const input = "<svg><a xlink:href=\"javascript:alert(1)\">x</a></svg>";
    const output = sanitize(input, ["svg", "a"], { allowJavaScript: true });
    const svg = firstTag(output, "svg");
    const anchor = svg?.querySelector("a");
    expect(anchor?.hasAttribute("xlink:href")).toBe(false);
  });

  test("is idempotent once sanitized", () => {
    const input = "<p><a href=\"javascript:alert(1)\">x</a><a>y</a></p>";
    const rules = ["p", "a"];
    const once = sanitize(input, rules, { allowJavaScript: false });
    const twice = sanitize(once, rules, { allowJavaScript: false });
    expect(twice).toBe(once);
  });

  test("treats tag-count rules as global, keeping earliest occurrences deterministically", () => {
    const input = "<a>first</a><p><a>second</a></p><div><a>third</a></div>";
    const output = sanitize(input, ["a", "p", "div"]);
    expect(bodyFrom(output).innerHTML).toBe("<a>first</a><p></p><div></div>");
  });

  test("removes disallowed tags but preserves allowed descendants", () => {
    const input = "<div><p><a>ok</a></p></div>";
    const output = sanitize(input, ["a", "p"]);
    expect(bodyFrom(output).innerHTML).toBe("<p><a>ok</a></p>");
  });

  test("does not allow style content without style rules even if style tag is allowed", () => {
    const input = "<style>.header{margin:0}</style>";
    const output = sanitize(input, ["style"]);
    const style = firstTag(output, "style");
    expect(style).toBe(null);
  });

  test("filters inline style attributes using style allowlist", () => {
    const input = "<p style=\"margin:0;color:red\">ok</p>";
    const output = sanitize(input, ["p", "p|style", "style|p|margin"]);
    const element = firstTag(output, "p");
    expect(element?.getAttribute("style")).toBe("margin:0");
  });

  test("drops inline style attributes when no allowed declarations survive", () => {
    const input = "<p style=\"color:red\">ok</p>";
    const output = sanitize(input, ["p", "p|style", "style|p|margin"]);
    const element = firstTag(output, "p");
    expect(element?.hasAttribute("style")).toBe(false);
  });

  test("allows inline style attributes with global wildcard rules", () => {
    const input = "<p style=\"margin:0;color:red\">ok</p>";
    const output = sanitize(input, ["p", "p|style", "style|*|color"]);
    const element = firstTag(output, "p");
    expect(element?.getAttribute("style")).toBe("color:red");
  });

  test("drops disallowed CSS properties even if selector is allowed", () => {
    const input = "<style>.header{margin:0;color:red}</style>";
    const output = sanitize(input, ["style", "style|.header|margin"]);
    const style = firstTag(output, "style");
    const css = style?.textContent ?? "";
    expect(css).toContain("margin");
    expect(css).not.toContain("color");
  });

  test("strips disallowed CSS selectors even if property is allowed", () => {
    const input = "<style>.header{margin:0}.footer{margin:1px}</style>";
    const output = sanitize(input, ["style", "style|.header|margin"]);
    const style = firstTag(output, "style");
    const css = style?.textContent ?? "";
    expect(css).toContain(".header");
    expect(css).not.toContain(".footer");
  });

  test("removes style tags when no allowed declarations survive filtering", () => {
    const input = "<style>.header{padding:2px}</style>";
    const output = sanitize(input, ["style", "style|.header|margin"]);
    expect(firstTag(output, "style")).toBe(null);
  });

  test("handles duplicate rules to increase allowance for styles", () => {
    const input = "<style>.header{margin:0}</style><style>.header{margin:1px}</style>";
    const output = sanitize(input, ["style", "style", "style|.header|margin"]);
    const styles = bodyFrom(output).querySelectorAll("style");
    expect(styles.length).toBe(2);
  });

  test("normalizes rule matching for attribute names to lowercase", () => {
    const input = "<a HREF=\"https://example.com\">x</a>";
    const output = sanitize(input, ["a", "a|href"]);
    const anchor = firstTag(output, "a");
    expect(anchor?.getAttribute("href")).toBe("https://example.com");
  });

  test("removes duplicate tags beyond allowance even when nested", () => {
    const input = "<div><a>one</a><div><a>two</a></div></div>";
    const output = sanitize(input, ["div", "div", "a"]);
    expect(bodyFrom(output).innerHTML).toBe("<div><a>one</a><div></div></div>");
  });

  test("does not allow data URLs with script payloads when allowJavaScript is false", () => {
    const input = "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">x</a>";
    const output = sanitize(input, ["a", "a|href"], { allowJavaScript: false });
    const anchor = firstTag(output, "a");
    expect(anchor?.getAttribute("href") ?? "").not.toMatch(/^data:/i);
  });

  test("sanitizeWithPolicy matches sanitize output", () => {
    const input = "<style>.header{margin:0}</style><a href=\"https://example.com\">x</a>";
    const rules = ["style", "style|.header|margin", "a", "a|href"];
    const config = { allowCommonAttributes: true, allowJavaScript: false };
    const policy = compileRules(rules, config);
    expect(sanitizeWithPolicy(input, policy)).toBe(sanitize(input, rules, config));
  });

  test("compileRules carries config into sanitizeWithPolicy", () => {
    const input = "<a title=\"ok\">x</a>";
    const rules = ["a"];
    const policy = compileRules(rules, { allowCommonAttributes: true });
    const output = sanitizeWithPolicy(input, policy);
    const anchor = firstTag(output, "a");
    expect(anchor?.getAttribute("title")).toBe("ok");
  });

  test("preserves text when tag counts are saturated", () => {
    const input = "<p>keep</p><span data-x=\"1\"><em>more</em> text</span><p>drop</p>";
    const output = sanitize(input, ["p"]);
    expect(bodyFrom(output).innerHTML).toBe("<p>keep</p>more text");
  });
});
