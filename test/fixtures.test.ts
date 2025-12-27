import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, test } from "vitest";
import { sanitize } from "../src/index.js";

const FIXTURES_DIR = resolve("test/files");
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

function configureHappyDomSettings(): void {
  const settings = (globalThis as { happyDOM?: { settings?: Record<string, boolean> } }).happyDOM?.settings;
  if (!settings) return;
  settings.disableJavaScriptEvaluation = true;
  settings.disableJavaScriptFileLoading = true;
  settings.disableCSSFileLoading = true;
  settings.disableIframePageLoading = true;
  settings.handleDisabledFileLoadingAsSuccess = true;
}

function docFrom(html: string): Document {
  configureHappyDomSettings();
  const parser = new DOMParser();
  return parser.parseFromString(html, "text/html");
}

function decodeNumericCharacterReferences(value: string): string {
  return value.replace(/&#(x?[0-9a-fA-F]+);?/g, (match, raw) => {
    const codePoint = raw.toLowerCase().startsWith("x") ? parseInt(raw.slice(1), 16) : parseInt(raw, 10);
    if (!Number.isFinite(codePoint)) {
      return match;
    }
    if (codePoint < 0 || codePoint > 0x10ffff) {
      return match;
    }
    return String.fromCodePoint(codePoint);
  });
}

function isDangerousUrl(value: string): boolean {
  const decoded = decodeNumericCharacterReferences(value);
  const compact = decoded.replace(/[\u0000-\u001F\u007F\s]+/g, "").toLowerCase();
  return compact.startsWith("javascript:") || compact.startsWith("data:");
}

function assertSafeOutput(html: string): void {
  const doc = docFrom(html);
  expect(doc.querySelector("script")).toBe(null);
  expect(doc.querySelector("style")).toBe(null);

  for (const element of Array.from(doc.querySelectorAll("*"))) {
    for (const attr of Array.from(element.attributes)) {
      const name = attr.name.toLowerCase();
      expect(name.startsWith("on")).toBe(false);
      if (!URL_ATTRS.has(name)) continue;
      if (name === "srcset") {
        const entries = attr.value.split(",");
        for (const entry of entries) {
          const urlPart = entry.trim().split(/\s+/)[0];
          if (!urlPart) continue;
          expect(isDangerousUrl(urlPart)).toBe(false);
        }
      } else {
        expect(isDangerousUrl(attr.value)).toBe(false);
      }
    }
  }
}

function buildRulesFromHtml(html: string): string[] {
  configureHappyDomSettings();
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");
  const elements = Array.from(doc.querySelectorAll("*"));
  const tagCounts = new Map<string, number>();
  const attrAllowlist = new Map<string, Set<string>>();

  for (const element of elements) {
    const tag = element.tagName.toLowerCase();
    tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);

    for (const attr of Array.from(element.attributes)) {
      const name = attr.name.toLowerCase();
      if (!attrAllowlist.has(tag)) {
        attrAllowlist.set(tag, new Set());
      }
      attrAllowlist.get(tag)!.add(name);
    }
  }

  const rules: string[] = [];
  for (const [tag, count] of tagCounts) {
    for (let i = 0; i < count; i += 1) {
      rules.push(tag);
    }
  }
  for (const [tag, attrs] of attrAllowlist) {
    for (const attr of attrs) {
      rules.push(`${tag}|${attr}`);
    }
  }
  return rules;
}

describe("real-world HTML fixtures", () => {
  const fixtures = readdirSync(FIXTURES_DIR)
    .filter((name) => name.endsWith(".html"))
    .sort((a, b) => a.localeCompare(b));

  for (const fixture of fixtures) {
    test(`sanitizes ${fixture} safely`, () => {
      const html = readFileSync(join(FIXTURES_DIR, fixture), "utf-8");
      const rules = buildRulesFromHtml(html);
      const output = sanitize(html, rules, { allowJavaScript: false });
      const second = sanitize(output, rules, { allowJavaScript: false });

      expect(second).toBe(output);
      assertSafeOutput(output);
    });
  }
});
