import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";
import * as browserEntry from "../src/index.browser.js";
import * as nodeEntry from "../src/index.js";

type Case = {
  name: string;
  html: string;
  rules: string[];
  config?: nodeEntry.SanitizerConfig;
};

const CASES: Case[] = [
  {
    name: "tag counts",
    html: "<p><a>one</a><a>two</a><a>three</a></p>",
    rules: ["p", "a", "a"]
  },
  {
    name: "unwraps disallowed tags but keeps descendants",
    html: "<div><p><a>ok</a></p></div>",
    rules: ["a", "p"]
  },
  {
    name: "attribute allowlist with common attributes",
    html: "<a href=\"https://example.com\" title=\"ok\" rel=\"nofollow\" data-x=\"1\">x</a>",
    rules: ["a"],
    config: { allowCommonAttributes: true }
  },
  {
    name: "hostile URLs across attributes",
    html:
      "<a href=\" java\nscript:alert(1)\">x</a>" +
      "<img src=\"https://example.com/ok.png\" srcset=\"javascript:alert(1) 1x\">" +
      "<form action=\"jav&#x61;script:alert(2)\"><button formaction=\"data:text/html,evil\">go</button></form>",
    rules: ["a", "a|href", "img", "img|src", "img|srcset", "form", "form|action", "button", "button|formaction"]
  },
  {
    name: "style tag filtering",
    html: "<style>@import url(x.css);.header{margin:0;padding:1px}.footer{margin:2px}</style><p>ok</p>",
    rules: ["style", "style|.header|margin", "p"]
  },
  {
    name: "inline style filtering",
    html: "<div style=\"color:red;background:url('https://example.com/x.png')\">x</div>",
    rules: ["div", "div|style", "style|div|color", "style|div|background"]
  },
  {
    name: "script removal",
    html: "<script>alert(1)</script><p>ok</p>",
    rules: ["script", "p"],
    config: { dangerouslyAllowJavaScript: false }
  },
  {
    name: "svg with dangerous attributes",
    html: "<svg><a xlink:href=\"javascript:alert(1)\">x</a></svg>",
    rules: ["svg", "a", "a|xlink:href"]
  }
];

describe("node and browser entrypoints stay in parity", () => {
  for (const { name, html, rules, config } of CASES) {
    test(name, () => {
      const fromNode = nodeEntry.sanitize(html, rules, config);
      const fromBrowser = browserEntry.sanitize(html, rules, config);
      expect(fromBrowser).toBe(fromNode);
    });
  }

  test("real-world fixture produces identical output", () => {
    const html = readFileSync(resolve("test/files/hn-guidelines.html"), "utf-8");
    const rules = ["html", "head", "body", "p", "p", "p", "a", "a|href", "div", "div", "span"];
    const fromNode = nodeEntry.sanitize(html, rules);
    const fromBrowser = browserEntry.sanitize(html, rules);
    expect(fromBrowser).toBe(fromNode);
  });

  test("a policy compiled by one entry works in the other", () => {
    const policy = nodeEntry.compileRules(["p", "a", "a|href"]);
    const html = "<p><a href=\"https://example.com\">ok</a><a>drop</a></p>";
    expect(browserEntry.sanitizeWithPolicy(html, policy)).toBe(nodeEntry.sanitizeWithPolicy(html, policy));
  });
});
