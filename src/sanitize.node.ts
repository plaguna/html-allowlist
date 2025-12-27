import createDOMPurify from "dompurify";
import type { WindowLike } from "dompurify";
import { Window } from "happy-dom";
import postcss from "postcss";
import valueParser from "postcss-value-parser";

export type SanitizerConfig = {
  allowCommonAttributes?: boolean;
  allowJavaScript?: boolean;
  maxPasses?: number;
};

export type CompiledPolicy = {
  tagCounts: Map<string, number>;
  attrAllowlist: Map<string, Set<string>>;
  styleAllowlist: Map<string, Set<string>>;
  config: SanitizerConfig;
};

const COMMON_ATTRS: Record<string, string[]> = {
  a: ["href", "title", "target", "rel"],
  img: ["src", "alt", "title", "width", "height"],
  html: ["lang"]
};
const COMMON_GLOBAL_ATTRS = ["class", "id"];
const STRUCTURAL_TAGS = new Set(["html", "head", "body"]);
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
let fallbackWindow: Window | null = null;
let cachedPurify: { window: WindowLike; purifier: ReturnType<typeof createDOMPurify> } | null = null;
const globalHappyDOM = (globalThis as { happyDOM?: { settings?: Record<string, boolean> } }).happyDOM;
configureHappyDomSettings(globalHappyDOM?.settings);

export function compileRules(rules: string[], config: SanitizerConfig = {}): CompiledPolicy {
  const tagCounts = new Map<string, number>();
  const attrAllowlist = new Map<string, Set<string>>();
  const styleAllowlist = new Map<string, Set<string>>();

  for (const rule of rules) {
    const parts = rule.split("|").map((part) => part.trim());
    if (parts.length === 1) {
      const tag = parts[0].toLowerCase();
      if (!tag) continue;
      tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);
      continue;
    }

    if (parts.length === 2) {
      const tag = parts[0].toLowerCase();
      const attr = parts[1].toLowerCase();
      if (!tag || !attr) continue;
      if (!attrAllowlist.has(tag)) {
        attrAllowlist.set(tag, new Set());
      }
      attrAllowlist.get(tag)!.add(attr);
      continue;
    }

    if (parts.length === 3 && parts[0].toLowerCase() === "style") {
      const selector = parts[1];
      const property = parts[2].toLowerCase();
      if (!selector || !property) continue;
      if (!styleAllowlist.has(selector)) {
        styleAllowlist.set(selector, new Set());
      }
      styleAllowlist.get(selector)!.add(property);
    }
  }

  return { tagCounts, attrAllowlist, styleAllowlist, config: { ...config } };
}

export function sanitize(html: string, rules: string[], config: SanitizerConfig = {}): string {
  return sanitizeWithPolicy(html, compileRules(rules, config));
}

export function sanitizeWithPolicy(html: string, policy: CompiledPolicy): string {
  const maxPasses = policy.config.maxPasses ?? 10;

  let current = html;
  for (let pass = 0; pass < maxPasses; pass += 1) {
    const next = sanitizeOnceWithPolicy(current, policy);
    if (next === current) {
      return next;
    }
    current = next;
  }

  return current;
}

function sanitizeOnceWithPolicy(html: string, policy: CompiledPolicy): string {
  const { tagCounts, attrAllowlist, styleAllowlist } = policy;
  const allowCommonAttributes = policy.config.allowCommonAttributes ?? false;
  const allowJavaScript = policy.config.allowJavaScript ?? false;
  const allowStyleTag = (tagCounts.get("style") ?? 0) > 0 && styleAllowlist.size > 0;
  let totalAllowedTags = 0;
  for (const [tag, count] of tagCounts) {
    if (STRUCTURAL_TAGS.has(tag)) continue;
    totalAllowedTags += count;
  }

  const happyDOM = (globalThis as { happyDOM?: { settings?: { disableJavaScriptEvaluation?: boolean } } })
    .happyDOM;
  configureHappyDomSettings(happyDOM?.settings);

  const parser = getDomParser();
  const doc = parser.parseFromString(html, "text/html");
  const root = doc.documentElement;
  const elements = [root, ...Array.from(root.querySelectorAll("*"))];
  const usedTagCounts = new Map<string, number>();
  let usedTotalTags = 0;
  let countsSaturated = totalAllowedTags === 0;

  for (const element of elements) {
    if (!element.isConnected) continue;
    const tag = element.tagName.toLowerCase();
    const isStructural = STRUCTURAL_TAGS.has(tag);

    if (!allowJavaScript && tag === "script") {
      element.remove();
      continue;
    }

    if (tag === "style" && !allowStyleTag) {
      element.remove();
      continue;
    }

    if (!isStructural) {
      const allowedCount = tagCounts.get(tag) ?? 0;
      if (countsSaturated) {
        if (allowedCount === 0) {
          unwrapElement(element);
        } else {
          element.remove();
        }
        continue;
      }

      if (allowedCount === 0) {
        unwrapElement(element);
        continue;
      }

      const usedCount = usedTagCounts.get(tag) ?? 0;
      if (usedCount >= allowedCount) {
        element.remove();
        continue;
      }

      usedTagCounts.set(tag, usedCount + 1);
      usedTotalTags += 1;
    }
    filterAttributes(element, tag, attrAllowlist, styleAllowlist, allowCommonAttributes, allowJavaScript);
    if (!isStructural && !countsSaturated && usedTotalTags >= totalAllowedTags) {
      countsSaturated = true;
    }

    if (tag === "style") {
      filterStyleElement(element, styleAllowlist);
      if (!element.isConnected) {
        continue;
      }
    }
  }

  const output = doc.documentElement.outerHTML;
  return applyDomPurify(output, policy);
}

function getDomParser(): any {
  if (globalThis.DOMParser) {
    return new globalThis.DOMParser();
  }
  if (!fallbackWindow) {
    fallbackWindow = new Window();
    configureHappyDomSettings(fallbackWindow.happyDOM?.settings);
  }
  return new (fallbackWindow as any).DOMParser();
}

function getDomWindow(): Window {
  const win = globalThis.window;
  if (win && typeof win.DOMParser === "function") {
    return win as unknown as Window;
  }
  if (!fallbackWindow) {
    fallbackWindow = new Window();
    configureHappyDomSettings(fallbackWindow.happyDOM?.settings);
  }
  return fallbackWindow;
}

function applyDomPurify(html: string, policy: CompiledPolicy): string {
  const domWindow = getDomWindow();
  if (!cachedPurify || (cachedPurify.window as unknown) !== (domWindow as unknown)) {
    cachedPurify = {
      window: domWindow as unknown as WindowLike,
      purifier: createDOMPurify(domWindow as unknown as WindowLike)
    };
  }
  const allowJavaScript = policy.config.allowJavaScript ?? false;
  const allowedTagSet = new Set<string>(policy.tagCounts.keys());
  for (const tag of STRUCTURAL_TAGS) {
    allowedTagSet.add(tag);
  }
  if (!allowJavaScript) {
    allowedTagSet.delete("script");
  }
  const allowedTags = Array.from(allowedTagSet);
  const allowedAttrs = new Set<string>();
  for (const attrs of policy.attrAllowlist.values()) {
    for (const attr of attrs) {
      allowedAttrs.add(attr);
    }
  }
  if (policy.config.allowCommonAttributes) {
    for (const attr of COMMON_GLOBAL_ATTRS) {
      allowedAttrs.add(attr);
    }
    for (const attrs of Object.values(COMMON_ATTRS)) {
      for (const attr of attrs) {
        allowedAttrs.add(attr);
      }
    }
  }
  return cachedPurify.purifier.sanitize(html, {
    ALLOWED_TAGS: allowedTags,
    ALLOWED_ATTR: Array.from(allowedAttrs),
    WHOLE_DOCUMENT: true
  }) as string;
}

function configureHappyDomSettings(
  settings?: Partial<{
    disableJavaScriptEvaluation: boolean;
    disableJavaScriptFileLoading: boolean;
    disableCSSFileLoading: boolean;
    disableIframePageLoading: boolean;
    handleDisabledFileLoadingAsSuccess: boolean;
  }>
): void {
  if (!settings) return;
  settings.disableJavaScriptEvaluation = true;
  settings.disableJavaScriptFileLoading = true;
  settings.disableCSSFileLoading = true;
  settings.disableIframePageLoading = true;
  settings.handleDisabledFileLoadingAsSuccess = true;
}

function unwrapElement(element: Element): void {
  const parent = element.parentNode;
  if (!parent) {
    element.remove();
    return;
  }
  while (element.firstChild) {
    parent.insertBefore(element.firstChild, element);
  }
  parent.removeChild(element);
}

function filterAttributes(
  element: Element,
  tag: string,
  attrAllowlist: Map<string, Set<string>>,
  styleAllowlist: Map<string, Set<string>>,
  allowCommonAttributes: boolean,
  allowJavaScript: boolean
): void {
  const allowedAttrs = new Set<string>(attrAllowlist.get(tag) ?? []);

  if (allowCommonAttributes) {
    for (const attr of COMMON_GLOBAL_ATTRS) {
      allowedAttrs.add(attr);
    }
    const common = COMMON_ATTRS[tag];
    if (common) {
      for (const attr of common) {
        allowedAttrs.add(attr);
      }
    }
  }

  for (const attr of Array.from(element.attributes)) {
    const name = attr.name.toLowerCase();
    if (!allowJavaScript && name.startsWith("on")) {
      element.removeAttribute(attr.name);
      continue;
    }

    if (!allowedAttrs.has(name)) {
      element.removeAttribute(attr.name);
      continue;
    }

    if (name === "style") {
      const filtered = filterInlineStyle(tag, attr.value, styleAllowlist);
      if (filtered.length === 0) {
        element.removeAttribute(attr.name);
      } else {
        element.setAttribute(attr.name, filtered);
      }
      continue;
    }

    if (!allowJavaScript && URL_ATTRS.has(name)) {
      const value = attr.value;
      if (isDangerousUrlValue(name, value)) {
        element.removeAttribute(attr.name);
      }
    }
  }
}

function filterInlineStyle(tag: string, value: string, styleAllowlist: Map<string, Set<string>>): string {
  const allowedProps = new Set<string>();
  const wildcard = styleAllowlist.get("*");
  if (wildcard) {
    for (const prop of wildcard) {
      allowedProps.add(prop);
    }
  }
  const tagSpecific = styleAllowlist.get(tag);
  if (tagSpecific) {
    for (const prop of tagSpecific) {
      allowedProps.add(prop);
    }
  }
  if (allowedProps.size === 0) {
    return "";
  }

  let root: postcss.Root;
  try {
    root = postcss.parse(`a{${value}}`);
  } catch {
    return "";
  }

  const rule = root.nodes?.find((node): node is postcss.Rule => node.type === "rule");
  if (!rule) {
    return "";
  }

  const decls: string[] = [];
  for (const node of rule.nodes ?? []) {
    if (node.type !== "decl") continue;
    const prop = node.prop.trim().toLowerCase();
    if (!allowedProps.has(prop)) continue;
    if (!isSafeCssValue(node.value)) continue;
    decls.push(`${prop}:${node.value.trim()}`);
  }

  return decls.join(";");
}

function isDangerousUrl(value: string): boolean {
  const decoded = decodeNumericCharacterReferences(value);
  const compact = decoded.replace(/[\u0000-\u001F\u007F\s]+/g, "").toLowerCase();
  return compact.startsWith("javascript:") || compact.startsWith("data:");
}

function isDangerousUrlValue(attrName: string, value: string): boolean {
  if (attrName === "srcset") {
    return isDangerousSrcset(value);
  }
  return isDangerousUrl(value);
}

function isDangerousSrcset(value: string): boolean {
  const entries = value.split(",");
  for (const entry of entries) {
    const urlPart = entry.trim().split(/\s+/)[0];
    if (!urlPart) continue;
    if (isDangerousUrl(urlPart)) {
      return true;
    }
  }
  return false;
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

function filterStyleElement(element: Element, styleAllowlist: Map<string, Set<string>>): void {
  const css = element.textContent ?? "";
  const filtered = filterCss(css, styleAllowlist);
  if (filtered.trim().length === 0) {
    element.remove();
    return;
  }
  element.textContent = filtered;
}

function filterCss(cssText: string, styleAllowlist: Map<string, Set<string>>): string {
  let root: postcss.Root;
  try {
    root = postcss.parse(cssText);
  } catch {
    return "";
  }

  root.walkAtRules((atRule) => {
    atRule.remove();
  });

  const rules: postcss.Rule[] = [];
  root.walkRules((rule) => {
    rules.push(rule);
  });

  for (const rule of rules) {
    const selectors = rule.selectors ?? [rule.selector];
    const allowedSelectors = selectors
      .map((selector) => selector.trim())
      .filter((selector) => styleAllowlist.has(selector));

    if (allowedSelectors.length === 0) {
      rule.remove();
      continue;
    }

    for (const selector of allowedSelectors) {
      const allowedProps = styleAllowlist.get(selector);
      if (!allowedProps) continue;
      const newRule = postcss.rule({ selector });

      for (const node of rule.nodes ?? []) {
        if (node.type !== "decl") continue;
        const prop = node.prop.trim().toLowerCase();
        if (!allowedProps.has(prop)) continue;
        if (!isSafeCssValue(node.value)) continue;
        newRule.append(node.clone());
      }

      if (newRule.nodes && newRule.nodes.length > 0) {
        rule.before(newRule);
      }
    }

    rule.remove();
  }

  return root.toString();
}

function isSafeCssValue(value: string): boolean {
  let hasUrl = false;
  valueParser(value).walk((node) => {
    if (node.type === "function" && node.value.toLowerCase() === "url") {
      hasUrl = true;
      return false;
    }
    return undefined;
  });
  return !hasUrl;
}
