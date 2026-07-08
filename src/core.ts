import createDOMPurify from "dompurify";
import type { WindowLike } from "dompurify";
import postcss from "postcss";
import valueParser from "postcss-value-parser";

export type SanitizerConfig = {
  allowCommonAttributes?: boolean;
  /**
   * Escape hatch: when `true`, the library's own JavaScript safety nets are
   * turned off and the allowlist rules carry the policy. `on*` attributes are
   * no longer stripped and `<script>` is no longer removed, so a handler or
   * script survives if (and only if) your rules explicitly permit the
   * tag/attribute carrying it. The library's `javascript:`/`data:` URL
   * pre-filter is also skipped — but DOMPurify still runs as an independent
   * second layer and blocks those schemes either way, so this flag does not
   * re-open dangerous URLs on its own. It does not "allow JavaScript"
   * wholesale; it removes the belt-and-suspenders that make the default output
   * safe to `innerHTML`, so enable it only when you fully trust your own rule
   * set. Named `dangerously*` on purpose.
   */
  dangerouslyAllowJavaScript?: boolean;
  allowDataImageUrls?: boolean;
  maxPasses?: number;
  outputFormat?: "document" | "fragment";
};

declare const compiledPolicyBrand: unique symbol;

/**
 * Opaque handle produced by `compileRules` and consumed by
 * `sanitizeWithPolicy`. Its internal layout is not part of the public API.
 */
export type CompiledPolicy = { readonly [compiledPolicyBrand]: "html-allowlist" };

export class RuleSyntaxError extends Error {
  readonly rule: string;

  constructor(rule: string, reason: string) {
    super(`Invalid rule ${JSON.stringify(rule)}: ${reason}`);
    this.name = "RuleSyntaxError";
    this.rule = rule;
  }
}

/**
 * Thrown when sanitization does not reach a fixed point within `maxPasses`.
 * The sanitizer re-runs over its own output until the result stops changing;
 * if that never happens within the budget, the partially-sanitized result is
 * withheld and this is thrown instead of returning output the sanitizer had
 * not finished transforming.
 */
export class ConvergenceError extends Error {
  readonly passes: number;

  constructor(passes: number) {
    super(
      `Sanitization did not reach a fixed point within ${passes} pass${passes === 1 ? "" : "es"} ` +
        `(maxPasses). The input keeps changing under repeated sanitization, which can indicate a ` +
        `pathological or adversarial document. The partially-sanitized result is withheld; raise ` +
        `maxPasses if your input legitimately needs more passes.`
    );
    this.name = "ConvergenceError";
    this.passes = passes;
  }
}

const POLICY_MARKER = Symbol.for("html-allowlist.policy");

type PolicyInternals = {
  [POLICY_MARKER]: true;
  tagCounts: Map<string, number>;
  attrAllowlist: Map<string, Set<string>>;
  styleAllowlist: Map<string, Set<string>>;
  config: SanitizerConfig;
};

/**
 * A DOM `Window` the sanitizer runs on. It must provide a `DOMParser` and the
 * standard DOM constructors DOMPurify needs (`Node`, `Element`,
 * `DocumentFragment`, `HTMLTemplateElement`, `NodeFilter`, `NamedNodeMap`,
 * `HTMLFormElement`). A browser `window`, a jsdom `window`, or a happy-dom
 * `Window` all satisfy this. Pass one to `createSanitizer` to run without the
 * bundled Node fallback (and without depending on `happy-dom` at all).
 */
export type SanitizerWindow = WindowLike;

/** The sanitizing functions returned by `createSanitizer`. */
export type Sanitizer = {
  sanitize(html: string, rules: string[], config?: SanitizerConfig): string;
  sanitizeWithPolicy(html: string, policy: CompiledPolicy): string;
};

/**
 * Low-level factory. Advanced: most consumers should use `createSanitizer`
 * (which takes a `Window`) or the package's default `sanitize` export. This
 * variant lets an entry point supply the parser and DOMPurify window
 * separately and hook `onPassStart` (used by the Node entry to reconfigure
 * happy-dom before each parse). Not re-exported from the package root.
 */
export type DomEnvironment = {
  getDomParser(): { parseFromString(html: string, type: string): Document };
  getDomWindow(): WindowLike;
  onPassStart?(): void;
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
// Raster image MIME types allowed in data: URLs when allowDataImageUrls is
// enabled. image/svg+xml is deliberately excluded, always, even if a caller
// asks for it: SVG can carry <script> and event handler attributes, so
// treating it as a "safe image" would reopen the exact XSS vector this
// allowlist blocks data: URLs to prevent.
const SAFE_DATA_IMAGE_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/bmp",
  "image/x-icon",
  "image/vnd.microsoft.icon",
  "image/avif"
]);
// DOMPurify's default ALLOWED_URI_REGEXP, widened to accept data: URIs.
// Only used when allowDataImageUrls is enabled, at which point our own
// pre-filtering (isDangerousUrl) has already stripped every data: URL
// except safe-mimetype ones on img|src / img|srcset, so it is safe to let
// DOMPurify's second pass stop re-blocking data: on those attributes.
const ALLOWED_URI_REGEXP_WITH_DATA =
  // eslint-disable-next-line no-useless-escape
  /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp|matrix|data):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i;
// CSS functions that can trigger fetches or script execution.
const DANGEROUS_CSS_FUNCTIONS = new Set([
  "url",
  "image",
  "image-set",
  "-webkit-image-set",
  "expression",
  "element",
  "-moz-element",
  "attr"
]);
// Legacy script-capable properties; never allowed even if explicitly listed.
const DANGEROUS_CSS_PROPS = new Set(["behavior", "-moz-binding"]);

export function compileRules(rules: string[], config: SanitizerConfig = {}): CompiledPolicy {
  const tagCounts = new Map<string, number>();
  const attrAllowlist = new Map<string, Set<string>>();
  const styleAllowlist = new Map<string, Set<string>>();

  for (const rule of rules) {
    if (typeof rule !== "string") {
      throw new RuleSyntaxError(String(rule), "rules must be strings");
    }
    const parts = rule.split("|").map((part) => part.trim());

    if (parts.length === 1) {
      const tag = parts[0].toLowerCase();
      if (!tag) throw new RuleSyntaxError(rule, "tag name is empty");
      if (/\s/.test(tag)) throw new RuleSyntaxError(rule, "tag name contains whitespace");
      tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);
      continue;
    }

    if (parts.length === 2) {
      const tag = parts[0].toLowerCase();
      const attr = parts[1].toLowerCase();
      if (!tag || !attr) throw new RuleSyntaxError(rule, "expected the form tag|attribute");
      if (/\s/.test(tag) || /\s/.test(attr)) {
        throw new RuleSyntaxError(rule, "tag and attribute names must not contain whitespace");
      }
      if (!attrAllowlist.has(tag)) {
        attrAllowlist.set(tag, new Set());
      }
      attrAllowlist.get(tag)!.add(attr);
      continue;
    }

    if (parts.length === 3) {
      if (parts[0].toLowerCase() !== "style") {
        throw new RuleSyntaxError(rule, "three-segment rules must start with style (style|selector|property)");
      }
      const selector = parts[1];
      const property = parts[2].toLowerCase();
      if (!selector || !property) throw new RuleSyntaxError(rule, "expected the form style|selector|property");
      if (/\s/.test(property)) throw new RuleSyntaxError(rule, "property name must not contain whitespace");
      if (!styleAllowlist.has(selector)) {
        styleAllowlist.set(selector, new Set());
      }
      styleAllowlist.get(selector)!.add(property);
      continue;
    }

    throw new RuleSyntaxError(rule, "too many segments");
  }

  const internals: PolicyInternals = {
    [POLICY_MARKER]: true,
    tagCounts,
    attrAllowlist,
    styleAllowlist,
    config: { ...config }
  };
  return internals as unknown as CompiledPolicy;
}

function toInternals(policy: CompiledPolicy): PolicyInternals {
  const candidate = policy as unknown as PolicyInternals | null;
  if (!candidate || candidate[POLICY_MARKER] !== true) {
    throw new TypeError("sanitizeWithPolicy expects a policy created by compileRules()");
  }
  return candidate;
}

/**
 * Bring your own DOM. Returns a sanitizer bound to `window`, deriving the
 * HTML parser from `window.DOMParser` and initializing DOMPurify against
 * `window`. Use this to run on a DOM implementation you control — a browser
 * `window`, a jsdom `window`, a linkedom window, or a happy-dom `Window` you
 * configured yourself — instead of relying on the Node entry's bundled
 * happy-dom fallback. Nothing here loads `happy-dom`.
 */
export function createSanitizer(window: SanitizerWindow): Sanitizer {
  return createSanitizerFromEnvironment({
    getDomParser: () => new window.DOMParser(),
    getDomWindow: () => window
  });
}

export function createSanitizerFromEnvironment(env: DomEnvironment): Sanitizer {
  let cachedPurify: { window: WindowLike; purifier: ReturnType<typeof createDOMPurify> } | null = null;

  function sanitize(html: string, rules: string[], config: SanitizerConfig = {}): string {
    return sanitizeWithPolicy(html, compileRules(rules, config));
  }

  function sanitizeWithPolicy(html: string, policy: CompiledPolicy): string {
    const internals = toInternals(policy);
    const maxPasses = internals.config.maxPasses ?? 10;

    let current = html;
    for (let pass = 0; pass < maxPasses; pass += 1) {
      const next = sanitizeOnce(current, internals);
      if (next === current) {
        return formatOutput(next, internals);
      }
      current = next;
    }

    // Exhausted the budget without two consecutive passes agreeing, so the
    // output is not a proven fixed point. Refuse to return it: a security
    // sanitizer should not hand back a result it had not finished
    // transforming. Note this needs at least two passes to ever succeed on
    // input that requires cleaning (one pass to clean, one to confirm).
    throw new ConvergenceError(maxPasses);
  }

  function formatOutput(html: string, policy: PolicyInternals): string {
    if ((policy.config.outputFormat ?? "fragment") !== "fragment") {
      return html;
    }
    const doc = env.getDomParser().parseFromString(html, "text/html");
    return doc.body ? doc.body.innerHTML : "";
  }

  function sanitizeOnce(html: string, policy: PolicyInternals): string {
    const { tagCounts, attrAllowlist, styleAllowlist } = policy;
    const allowCommonAttributes = policy.config.allowCommonAttributes ?? false;
    const allowJavaScript = policy.config.dangerouslyAllowJavaScript ?? false;
    const allowDataImageUrls = policy.config.allowDataImageUrls ?? false;
    const allowStyleTag = (tagCounts.get("style") ?? 0) > 0 && styleAllowlist.size > 0;
    let totalAllowedTags = 0;
    for (const [tag, count] of tagCounts) {
      if (STRUCTURAL_TAGS.has(tag)) continue;
      totalAllowedTags += count;
    }

    env.onPassStart?.();

    const parser = env.getDomParser();
    // Wrapping in <body> keeps leading/trailing whitespace and any content
    // that would otherwise land "before html" attached to the body, so
    // fragment output round-trips through another sanitize() call unchanged.
    const doc = parser.parseFromString(`<body>${html}</body>`, "text/html");
    const root = doc.documentElement;
    const elements: Element[] = [];
    collectElements(root, elements);
    const usedTagCounts = new Map<string, number>();
    let usedTotalTags = 0;
    let countsSaturated = totalAllowedTags === 0;

    for (const element of elements) {
      if (!isElementLive(element, root)) continue;
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
      filterAttributes(
        element,
        tag,
        attrAllowlist,
        styleAllowlist,
        allowCommonAttributes,
        allowJavaScript,
        allowDataImageUrls
      );
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

  function applyDomPurify(html: string, policy: PolicyInternals): string {
    const domWindow = env.getDomWindow();
    ensureSpecCompliantNodeName(domWindow);
    if (!cachedPurify || (cachedPurify.window as unknown) !== (domWindow as unknown)) {
      cachedPurify = {
        window: domWindow,
        purifier: createDOMPurify(domWindow)
      };
    }
    const allowJavaScript = policy.config.dangerouslyAllowJavaScript ?? false;
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
    // Only widen past DOMPurify's default scheme allowlist when our own
    // pre-filtering (isDangerousUrl) is actually guaranteed to have run and
    // constrained data: to safe-mimetype img|src / img|srcset values. That
    // pre-filtering is skipped entirely when dangerouslyAllowJavaScript is
    // true, so the regexp must stay at DOMPurify's default in that combination.
    const allowDataImageUrls = !allowJavaScript && (policy.config.allowDataImageUrls ?? false);
    return cachedPurify.purifier.sanitize(html, {
      ALLOWED_TAGS: allowedTags,
      ALLOWED_ATTR: Array.from(allowedAttrs),
      WHOLE_DOCUMENT: true,
      ...(allowDataImageUrls ? { ALLOWED_URI_REGEXP: ALLOWED_URI_REGEXP_WITH_DATA } : {})
    }) as string;
  }

  return { sanitize, sanitizeWithPolicy };
}

/**
 * happy-dom hardcodes `Node.prototype.nodeName` to return "" and shadows it
 * per subclass (Element, Comment, …). Browsers instead implement it as a
 * single getter on Node.prototype that works for every node type. DOMPurify
 * >=3.4.6 caches that base getter to defeat DOM clobbering, so under
 * happy-dom every element reads as nodeName "" and gets removed (and the
 * child-hoisting fallback crashes happy-dom at document level).
 *
 * Make the base getter spec-compliant: delegate to the most-derived shadowing
 * getter for the instance, exactly what plain `.nodeName` access resolves to.
 * The patch is probe-guarded (a no-op on spec-compliant DOMs, including real
 * browsers) and idempotent; observable behavior of normal property access is
 * unchanged.
 */
function ensureSpecCompliantNodeName(domWindow: WindowLike): void {
  const win = domWindow as unknown as { Node?: { prototype: object }; document?: Document };
  const nodeProto = win.Node?.prototype;
  const doc = win.document;
  if (!nodeProto || !doc) return;
  const baseDesc = Object.getOwnPropertyDescriptor(nodeProto, "nodeName");
  if (!baseDesc?.get || !baseDesc.configurable) return;

  const probe = doc.createElement("div");
  if (baseDesc.get.call(probe) === probe.nodeName) return;

  const baseGet = baseDesc.get;
  Object.defineProperty(nodeProto, "nodeName", {
    configurable: true,
    enumerable: baseDesc.enumerable,
    get(this: Node) {
      let proto = Object.getPrototypeOf(this) as object | null;
      while (proto && proto !== nodeProto) {
        const desc = Object.getOwnPropertyDescriptor(proto, "nodeName");
        if (desc?.get) return desc.get.call(this);
        proto = Object.getPrototypeOf(proto);
      }
      return baseGet.call(this);
    }
  });
}

// The parsed children of a <template> do not live among its childNodes; the
// parser moves them into a separate inert DocumentFragment exposed as
// `.content`. A plain `querySelectorAll("*")` / childNodes walk therefore never
// descends into template content, so without this every allowlist check (tag
// counts, per-tag attribute scoping, URL and CSS pre-filtering, the hard
// data:image/svg+xml exclusion) would silently skip anything inside a
// <template> and lean entirely on DOMPurify — which is unsound, because our
// data: URL widening tells DOMPurify to trust a pre-filter that never ran there.
// Collect in pre-order, descending into template content in place.
function collectElements(element: Element, out: Element[]): void {
  out.push(element);
  for (const child of Array.from(element.children)) {
    collectElements(child, out);
  }
  const content = (element as Partial<HTMLTemplateElement>).content;
  if (content && typeof (content as DocumentFragment).children !== "undefined") {
    for (const child of Array.from((content as DocumentFragment).children)) {
      collectElements(child, out);
    }
  }
}

// Whether an element is still attached to something that will appear in the
// output. Elements are collected up front, then removed/unwrapped as the pass
// proceeds, so we must re-check liveness before processing each one. `isConnected`
// cannot be used: it is false for everything inside a template's content
// fragment (a fragment is never connected to a document). Instead walk to the
// root: reaching `root` means it is in the live tree; reaching a parentless
// DocumentFragment means it is still inside live template content; reaching a
// parentless element means it was detached this pass.
function isElementLive(element: Element, root: Element): boolean {
  let node: Node | null = element;
  while (node) {
    if (node === root) return true;
    const parent: Node | null = node.parentNode;
    if (!parent) {
      return node.nodeType === 11; // DOCUMENT_FRAGMENT_NODE => live template content
    }
    node = parent;
  }
  return false;
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
  allowJavaScript: boolean,
  allowDataImageUrls: boolean
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
      const allowSafeDataImage = allowDataImageUrls && tag === "img" && (name === "src" || name === "srcset");
      if (isDangerousUrlValue(name, value, allowSafeDataImage)) {
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
    if (DANGEROUS_CSS_PROPS.has(prop)) continue;
    if (!isSafeCssValue(node.value)) continue;
    decls.push(`${prop}:${node.value.trim()}`);
  }

  return decls.join(";");
}

function isDangerousUrl(value: string, allowSafeDataImage = false): boolean {
  const decoded = decodeNumericCharacterReferences(value);
  const compact = decoded.replace(/[\u0000-\u001F\u007F\s]+/g, "").toLowerCase();
  if (compact.startsWith("javascript:")) return true;
  if (compact.startsWith("data:")) {
    return !(allowSafeDataImage && isSafeDataImageUrl(compact));
  }
  return false;
}

// `compact` is already lowercased and stripped of whitespace/control chars,
// and is known to start with "data:". image/svg+xml is never treated as
// safe here (see SAFE_DATA_IMAGE_TYPES), regardless of config.
function isSafeDataImageUrl(compact: string): boolean {
  const rest = compact.slice("data:".length);
  const commaIndex = rest.indexOf(",");
  if (commaIndex === -1) return false;
  const meta = rest.slice(0, commaIndex);
  const mimeType = meta.split(";")[0];
  return SAFE_DATA_IMAGE_TYPES.has(mimeType);
}

function isDangerousUrlValue(attrName: string, value: string, allowSafeDataImage = false): boolean {
  if (attrName === "srcset") {
    return isDangerousSrcset(value, allowSafeDataImage);
  }
  return isDangerousUrl(value, allowSafeDataImage);
}

function isDangerousSrcset(value: string, allowSafeDataImage = false): boolean {
  for (const url of parseSrcsetUrls(value)) {
    if (isDangerousUrl(url, allowSafeDataImage)) {
      return true;
    }
  }
  return false;
}

const SRCSET_WHITESPACE = new Set([" ", "\t", "\n", "\r", "\f"]);

// A simplified version of the WHATWG "parse a srcset attribute" algorithm,
// used only to recover each entry's URL. `value.split(",")` is not safe here
// because a URL can itself contain a comma (most notably a data: URI, whose
// syntax always has one between the MIME header and the payload) -- naively
// splitting on every comma cuts such a URL in half. This tokenizer mirrors
// the spec's actual boundary rule instead: an entry's URL is the run of
// non-whitespace characters, and (when present) its descriptor extends to
// the next comma that isn't nested inside parentheses.
function parseSrcsetUrls(value: string): string[] {
  const urls: string[] = [];
  const len = value.length;
  let i = 0;

  while (i < len) {
    while (i < len && (SRCSET_WHITESPACE.has(value[i]) || value[i] === ",")) i++;
    if (i >= len) break;

    const urlStart = i;
    while (i < len && !SRCSET_WHITESPACE.has(value[i])) i++;
    const url = value.slice(urlStart, i);

    const strippedUrl = url.replace(/,+$/, "");
    urls.push(strippedUrl);
    if (strippedUrl !== url) {
      // Trailing comma(s) on the URL token itself are the entry separator;
      // there is no descriptor to skip past.
      continue;
    }

    while (i < len && SRCSET_WHITESPACE.has(value[i])) i++;
    let parenDepth = 0;
    while (i < len) {
      const ch = value[i];
      if (ch === "(") {
        parenDepth += 1;
      } else if (ch === ")") {
        if (parenDepth > 0) parenDepth -= 1;
      } else if (ch === "," && parenDepth === 0) {
        i += 1;
        break;
      }
      i += 1;
    }
  }

  return urls;
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
        if (DANGEROUS_CSS_PROPS.has(prop)) continue;
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

// Resolve CSS escape sequences the way a browser's tokenizer does, so a
// dangerous function name cannot be smuggled past the check below in escaped
// form. In CSS, `\75rl(...)` and `\75 rl(...)` both tokenize to `url(...)`,
// and `\65xpression(...)` to `expression(...)`; postcss-value-parser preserves
// the backslashes verbatim (it treats `\75rl` as an opaque function name and
// even splits `\75 rl` across a word/space/function boundary), so matching on
// the raw token name is fail-open. Decoding the whole value first collapses
// every escaped spelling of a name back to its canonical form before parsing.
// A hex escape is 1-6 hex digits followed by at most one whitespace; any other
// escaped code point stands for that literal character.
function decodeCssEscapes(value: string): string {
  return value.replace(
    /\\([0-9a-fA-F]{1,6})[ \t\n\r\f]?|\\([^\n\r\f0-9a-fA-F])/g,
    (match, hex: string | undefined, literal: string | undefined) => {
      if (hex !== undefined) {
        const codePoint = parseInt(hex, 16);
        if (codePoint === 0 || codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
          return "�";
        }
        return String.fromCodePoint(codePoint);
      }
      return literal ?? match;
    }
  );
}

function isSafeCssValue(value: string): boolean {
  let dangerous = false;
  valueParser(decodeCssEscapes(value)).walk((node) => {
    if (node.type === "function" && DANGEROUS_CSS_FUNCTIONS.has(node.value.toLowerCase())) {
      dangerous = true;
      return false;
    }
    return undefined;
  });
  return !dangerous;
}
