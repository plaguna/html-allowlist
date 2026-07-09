// Coverage-guided fuzz target for sanitize() (Jazzer.js / libFuzzer).
//
// Each input picks one of two rule-generation modes (selected by a leading
// fuzzed bit), then a config (drawn from fixed pools so compileRules always
// succeeds and every exec reaches the HTML pipeline) and an HTML document
// (the remaining bytes, which is what the mutator spends most of its energy
// on):
//
//   - pooled: rules are drawn from small fixed pools, independent of the
//     HTML. Most mutated content doesn't match any rule and gets dropped,
//     so this mode is best at exercising rejection/stripping paths.
//   - derived: rules are reverse-engineered from the HTML itself (every tag,
//     tag|attr, and style property it contains is allowed). This guarantees
//     whatever weird structure the mutator finds is retained and pushed
//     through the transform paths (URL/style rewriting, normalization)
//     instead of silently stripped -- including tags/attrs that never
//     appear in the pooled mode's fixed lists.
//
// Both modes still assert the same invariants below with
// dangerouslyAllowJavaScript at its default (false), including when the
// derived rules explicitly allow <script> or on*: the library's hardcoded
// denylist must still win over whatever the rules say.
//
// This target is an invariant oracle, not just a crash detector. With
// dangerouslyAllowJavaScript at its default (false) the library guarantees,
// no matter what the rules say:
//   - no <script> element survives
//   - no on* attribute survives
//   - no javascript: URL survives on a URL attribute
//   - data: URLs survive only as safe raster images on img|src / img|srcset,
//     and only when allowDataImageUrls is enabled
//   - output is a fixed point: sanitize(output) === output
// Any violation, and any exception other than ConvergenceError, is thrown
// and reported by Jazzer.js as a finding.
//
// Known blind spot: the oracle re-parses output with the same happy-dom
// parser the sanitizer uses, so parser-differential (mXSS) issues between
// happy-dom and real browsers are out of scope here; those are covered by
// the DOMPurify layer and the static corpus in test/xss-vectors.test.ts.
//
// Run: npm run fuzz  (or: npx jazzer fuzz/sanitize.fuzz.js fuzz/corpus/sanitize)

import { FuzzedDataProvider } from "@jazzer.js/core";
import { Window } from "happy-dom";
import { ConvergenceError, sanitize } from "../dist/index.js";

// IMPORTANT: do not run this target with Jazzer's `--sync` flag, even though
// Jazzer suggests it (the fuzz function does return synchronously).
//
// happy-dom retains DOM nodes through WeakRef/FinalizationRegistry, and V8
// keeps WeakRef targets alive until the end of the current *job*. Under
// `--sync` the fuzzer never returns to the event loop, so the job never ends,
// every parsed Document stays reachable, and RSS climbs until libFuzzer
// reports a spurious out-of-memory. In async mode each iteration ends its job
// and RSS plateaus (~1GB) indefinitely. This is not a leak in the library:
// a plain synchronous `for` loop around sanitize() reproduces the growth, and
// yielding to the event loop every N calls makes it flat.

const TAG_POOL = [
  "a", "p", "div", "span", "style", "script", "svg", "math", "template",
  "img", "form", "object", "embed", "table", "ul", "li", "b", "html", "body",
  // Object.prototype-inherited property names: a plain-object lookup keyed
  // by tag name (like the fixed COMMON_ATTRS bug) returns the inherited
  // value instead of undefined for these. Kept in the pool so pooled mode
  // keeps probing this surface, not just the document-derived mode that
  // found the original bug.
  "constructor", "toString", "valueOf", "hasOwnProperty", "__proto__"
];
const ATTR_RULE_POOL = [
  "a|href", "a|onclick", "a|style", "img|src", "img|srcset", "img|onerror",
  "div|style", "div|id", "svg|onload", "form|action", "object|data",
  "span|style", "template|id", "b|style"
];
const STYLE_RULE_POOL = [
  "style|div|background", "style|*|color", "style|*|background",
  "style|.note|margin", "style|span|width", "style|*|width",
  "style|script|color", "style|#main|display"
];

const oracleWindow = new Window();
if (oracleWindow.happyDOM?.settings) {
  const settings = oracleWindow.happyDOM.settings;
  settings.disableJavaScriptEvaluation = true;
  settings.disableJavaScriptFileLoading = true;
  settings.disableCSSFileLoading = true;
  settings.disableIframePageLoading = true;
  settings.handleDisabledFileLoadingAsSuccess = true;
}

const URL_ATTRS = new Set([
  "href", "src", "xlink:href", "action", "formaction", "poster", "srcset",
  "data", "codebase", "archive", "cite", "longdesc", "usemap", "background",
  "profile", "icon", "manifest"
]);
const SAFE_DATA_IMAGE_TYPES = new Set([
  "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp",
  "image/x-icon", "image/vnd.microsoft.icon", "image/avif"
]);

function compactUrl(value) {
  return value.replace(/[\u0000-\u001F\u007F\s]+/g, "").toLowerCase();
}

const SRCSET_WHITESPACE = new Set([" ", "\t", "\n", "\r", "\f"]);

// Mirrors src/core.ts's parseSrcsetUrls: a candidate's URL is the run of
// non-whitespace characters (which can itself contain a comma, e.g. a data:
// URI's mimetype/payload separator), not a naive split(","). Without this,
// a value like "1x,data:image/svg+xmlm" -- one inert, non-"data:"-prefixed
// token per the WHATWG grammar -- gets misread as two entries and produces
// a false-positive finding.
function parseSrcsetUrls(value) {
  const urls = [];
  const len = value.length;
  let i = 0;
  while (i < len) {
    while (i < len && (SRCSET_WHITESPACE.has(value[i]) || value[i] === ",")) i += 1;
    if (i >= len) break;
    const urlStart = i;
    while (i < len && !SRCSET_WHITESPACE.has(value[i])) i += 1;
    const url = value.slice(urlStart, i);
    const strippedUrl = url.replace(/,+$/, "");
    urls.push(strippedUrl);
    if (strippedUrl !== url) continue;
    while (i < len && SRCSET_WHITESPACE.has(value[i])) i += 1;
    let parenDepth = 0;
    while (i < len) {
      const ch = value[i];
      if (ch === "(") parenDepth += 1;
      else if (ch === ")") { if (parenDepth > 0) parenDepth -= 1; }
      else if (ch === "," && parenDepth === 0) { i += 1; break; }
      i += 1;
    }
  }
  return urls;
}

function isForbiddenUrl(compact, allowSafeDataImage) {
  if (compact.startsWith("javascript:") || compact.startsWith("vbscript:")) return true;
  if (!compact.startsWith("data:")) return false;
  if (!allowSafeDataImage) return true;
  const rest = compact.slice("data:".length);
  const commaIndex = rest.indexOf(",");
  if (commaIndex === -1) return true;
  return !SAFE_DATA_IMAGE_TYPES.has(rest.slice(0, commaIndex).split(";")[0]);
}

function assertInvariants(output, allowDataImageUrls) {
  const doc = new oracleWindow.DOMParser().parseFromString(output, "text/html");
  const stack = [doc.documentElement];
  while (stack.length > 0) {
    const element = stack.pop();
    if (!element) continue;
    const tag = element.tagName.toLowerCase();
    if (tag === "script") {
      throw new Error(`Finding: <script> element survived sanitization: ${output}`);
    }
    for (const attr of Array.from(element.attributes)) {
      const name = attr.name.toLowerCase();
      if (name.startsWith("on")) {
        throw new Error(`Finding: event handler ${name} survived on <${tag}>: ${output}`);
      }
      if (URL_ATTRS.has(name)) {
        const allowSafeDataImage =
          allowDataImageUrls && tag === "img" && (name === "src" || name === "srcset");
        const values = name === "srcset" ? parseSrcsetUrls(attr.value) : [attr.value];
        for (const value of values) {
          if (isForbiddenUrl(compactUrl(value), allowSafeDataImage)) {
            throw new Error(`Finding: dangerous URL survived in ${name} on <${tag}>: ${attr.value}`);
          }
        }
      }
    }
    for (const child of Array.from(element.children)) {
      stack.push(child);
    }
    // Gate on tagName before touching `.content`, for the same reason the
    // library does (see collectElements in src/core.ts): reading `.content`
    // on a <form> triggers a named-item lookup that throws on a quote-bearing
    // id, which would surface here as a bogus finding rather than a real one.
    if (tag !== "template") continue;
    const content = element.content;
    if (content && content.children) {
      for (const child of Array.from(content.children)) {
        stack.push(child);
      }
    }
  }
}

// ConvergenceError is a documented outcome, not a defect.
//
// The other two cases are KNOWN UPSTREAM BUGS in happy-dom, matched as
// narrowly as possible so that every other exception stays a genuine finding.
// Both are recognized here only so the fuzzer keeps hunting for *new* defects
// instead of rediscovering these on every run; each is pinned in
// test/sanitize.test.ts with `test.fails`, so it surfaces the moment happy-dom
// fixes it. Remove the pin and the branch here together.
//
//  1. HTMLFormElement resolves named properties by interpolating the form's id
//     into a CSS selector without escaping it, so a quote-bearing id makes any
//     property read on that form throw. DOMPurify's walk reads
//     `currentNode.content` on every node, so it trips this whenever a <form>
//     keeps such an id. Neither DOMPurify nor this library can intercept the
//     read. Minimal repro: sanitize('<form id=&quot;></form>', ['form','form|id']).
//
//  2. HTMLSerializer reads `.content` on any element named "template",
//     including an SVG-namespaced <template>, which has no `.content`.
//     Serializing then throws. This is pure happy-dom -- reproducible with
//     `document.body.innerHTML = '<svg><template>x</template></svg>';
//     document.documentElement.outerHTML` -- and this library cannot avoid
//     serializing. Minimal repro:
//     sanitize('<svg><template>x</template></svg>', ['svg','template']).
function isExpectedError(error) {
  if (error instanceof ConvergenceError) return true;
  if (!(error instanceof Error)) return false;

  const isUnescapedFormSelectorBug =
    error.name === "DOMException" &&
    /is not a valid selector/.test(error.message) &&
    /\[form=/.test(error.message);

  const isSvgTemplateSerializerBug =
    error.name === "TypeError" && /Symbol\(nodeArray\)/.test(error.message);

  return isUnescapedFormSelectorBug || isSvgTemplateSerializerBug;
}

// Reverse-engineers a rule list that allows exactly the tags, attributes,
// and style properties already present in `html`, so sanitize() retains
// (and transforms) the mutator's own structure instead of dropping it.
// Style rules use the `*` selector: the oracle only cares whether a
// property is allowed *somewhere*, not which selector matched.
function deriveRulesFromDocument(html) {
  const doc = new oracleWindow.DOMParser().parseFromString(html, "text/html");
  const tagRules = new Set();
  const attrRules = new Set();
  const styleProps = new Set();

  const collectStyleProps = (text) => {
    for (const match of text.matchAll(/([a-zA-Z-]+)\s*:/g)) {
      styleProps.add(match[1].toLowerCase());
    }
  };

  // HTML's parser is far more permissive about tag/attribute names than the
  // rule mini-language: happy-dom happily parses `<|emplate>` as a literal
  // tag named "|emplate". Feeding a name containing "|" straight into a
  // rule string changes its segment count (rule.split("|") in compileRules)
  // and throws RuleSyntaxError, which isn't a real defect -- so names that
  // can't round-trip through the grammar are skipped rather than derived.
  const isRepresentable = (name) => name.length > 0 && !name.includes("|");

  const stack = [doc.documentElement];
  while (stack.length > 0) {
    const element = stack.pop();
    if (!element) continue;
    const tag = element.tagName.toLowerCase();
    if (isRepresentable(tag)) tagRules.add(tag);
    for (const attr of Array.from(element.attributes)) {
      const name = attr.name.toLowerCase();
      if (isRepresentable(tag) && isRepresentable(name)) {
        attrRules.add(`${tag}|${name}`);
      }
      if (name === "style") collectStyleProps(attr.value);
    }
    if (tag === "style" && element.textContent) {
      collectStyleProps(element.textContent);
    }
    for (const child of Array.from(element.children)) {
      stack.push(child);
    }
    // Same tagName gate as assertInvariants, for the same reason.
    if (tag !== "template") continue;
    const content = element.content;
    if (content && content.children) {
      for (const child of Array.from(content.children)) {
        stack.push(child);
      }
    }
  }

  const styleRules = Array.from(styleProps, (prop) => `style|*|${prop}`);
  return [...tagRules, ...attrRules, ...styleRules];
}

export function fuzz(data) {
  const fdp = new FuzzedDataProvider(data);
  const deriveRulesFromDoc = fdp.consumeBoolean();

  let rules = [];
  if (!deriveRulesFromDoc) {
    const tagRuleCount = fdp.consumeIntegralInRange(0, 5);
    for (let i = 0; i < tagRuleCount; i += 1) {
      rules.push(fdp.pickValue(TAG_POOL));
    }
    const attrRuleCount = fdp.consumeIntegralInRange(0, 4);
    for (let i = 0; i < attrRuleCount; i += 1) {
      rules.push(fdp.pickValue(ATTR_RULE_POOL));
    }
    const styleRuleCount = fdp.consumeIntegralInRange(0, 3);
    for (let i = 0; i < styleRuleCount; i += 1) {
      rules.push(fdp.pickValue(STYLE_RULE_POOL));
    }
  }

  const config = {
    allowCommonAttributes: fdp.consumeBoolean(),
    allowDataImageUrls: fdp.consumeBoolean(),
    dangerouslyAllowJavaScript: false,
    outputFormat: fdp.consumeBoolean() ? "fragment" : "document",
    maxPasses: 10
  };

  const html = fdp.consumeRemainingAsString();

  if (deriveRulesFromDoc) {
    rules = deriveRulesFromDocument(html);
  }

  let output;
  try {
    output = sanitize(html, rules, config);
  } catch (error) {
    if (isExpectedError(error)) return;
    throw error;
  }

  assertInvariants(output, config.allowDataImageUrls);

  let again;
  try {
    again = sanitize(output, rules, config);
  } catch (error) {
    if (isExpectedError(error)) return;
    throw error;
  }

  if (again !== output) {
    throw new Error(
      `Finding: sanitize is not idempotent.\nfirst:  ${JSON.stringify(output)}\nsecond: ${JSON.stringify(again)}`
    );
  }
}

// Exported for fuzz/generate-corpus.js, which hand-encodes FuzzedDataProvider
// byte streams that pick specific entries from these pools -- keeping a
// single source of truth means the generator can't silently drift from the
// indices this file actually reads.
export { TAG_POOL, ATTR_RULE_POOL, STYLE_RULE_POOL };
