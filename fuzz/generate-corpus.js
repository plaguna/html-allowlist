// Generates curated seed files for fuzz/sanitize.fuzz.js by hand-encoding
// the exact FuzzedDataProvider byte stream each scenario needs, instead of
// hoping the mutator stumbles onto a rule+HTML pairing that actually
// exercises a given feature.
//
// Motivation: this fuzz target's HTML is either (a) independent of the
// picked rules (pooled mode) or (b) derived from whatever HTML the mutator
// already produced (derived mode). Neither path guarantees coverage of a
// *specific* rule-grammar feature -- a multiset tag count, a style-selector
// shape, a particular attribute on a particular tag -- on demand. This
// script goes the other way: given an intended rule/feature, emit the
// minimal HTML that satisfies (and exercises) it, encoded as a seed
// FuzzedDataProvider will decode back into that exact scenario.
//
// Run: node fuzz/generate-corpus.js
// Output: fuzz/corpus/sanitize/generated-<name>
//
// FuzzedDataProvider byte layout (verified against
// @jazzer.js/core/dist/FuzzedDataProvider.js): consumeBoolean/
// consumeIntegralInRange pop single bytes from the *back* of the buffer, in
// call order, one byte per call for every range this harness uses (all
// ranges here need only 1 byte per ceil(log2(range+1)/8)).
// consumeRemainingAsString then reads whatever is left from the *front*.
// So a seed is: [HTML bytes][control bytes in REVERSE call order].

import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { TAG_POOL, ATTR_RULE_POOL, STYLE_RULE_POOL } from "./sanitize.fuzz.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(__dirname, "corpus", "sanitize");

function byteFor(value, poolLength) {
  if (value < 0 || value >= poolLength) {
    throw new Error(`value ${value} out of range for pool length ${poolLength}`);
  }
  return value; // numBytesToConsume is always 1 for these small ranges, so byte % (range+1) === value when value < range+1.
}

function poolIndex(pool, entry) {
  const index = pool.indexOf(entry);
  if (index === -1) throw new Error(`"${entry}" is not in the pool: ${pool.join(", ")}`);
  return index;
}

// Encodes a pooled-mode seed: explicit tag/attr/style rule picks (as pool
// entries, repeats allowed to build multiset tag counts) + config + html.
function encodePooledSeed({ tags = [], attrs = [], styles = [], config = {}, html }) {
  if (tags.length > 5) throw new Error("tagRuleCount pool range is 0..5");
  if (attrs.length > 4) throw new Error("attrRuleCount pool range is 0..4");
  if (styles.length > 3) throw new Error("styleRuleCount pool range is 0..3");

  const callOrder = [];
  callOrder.push(0); // deriveRulesFromDoc = false (even byte)
  callOrder.push(byteFor(tags.length, 6));
  for (const tag of tags) callOrder.push(byteFor(poolIndex(TAG_POOL, tag), TAG_POOL.length));
  callOrder.push(byteFor(attrs.length, 5));
  for (const attr of attrs) callOrder.push(byteFor(poolIndex(ATTR_RULE_POOL, attr), ATTR_RULE_POOL.length));
  callOrder.push(byteFor(styles.length, 4));
  for (const style of styles) callOrder.push(byteFor(poolIndex(STYLE_RULE_POOL, style), STYLE_RULE_POOL.length));
  callOrder.push(config.allowCommonAttributes ? 1 : 0);
  callOrder.push(config.allowDataImageUrls ? 1 : 0);
  callOrder.push(config.fragment === false ? 0 : 1); // outputFormat: default to "fragment"

  const controlBytes = Buffer.from(callOrder.slice().reverse());
  return Buffer.concat([Buffer.from(html, "utf-8"), controlBytes]);
}

// Encodes a derived-mode seed: only the config booleans + html matter, since
// deriveRulesFromDocument() reconstructs rules from the HTML itself. Used
// for curated adversarial documents where the *point* is what rules get
// derived from them (prototype-colliding names, ambiguous srcset commas,
// nested namespace edge cases), not a specific pool combination.
function encodeDerivedSeed({ config = {}, html }) {
  const callOrder = [
    1, // deriveRulesFromDoc = true (odd byte)
    config.allowCommonAttributes ? 1 : 0,
    config.allowDataImageUrls ? 1 : 0,
    config.fragment === false ? 0 : 1
  ];
  const controlBytes = Buffer.from(callOrder.slice().reverse());
  return Buffer.concat([Buffer.from(html, "utf-8"), controlBytes]);
}

const pooledScenarios = {
  // Multiset tag counts: the same pool entry picked repeatedly allows that
  // many instances; a document with one extra sibling checks that the
  // (N+1)th is actually dropped once the count is saturated.
  "multiset-tag-count": encodePooledSeed({
    tags: ["div", "div", "div"],
    html: "<div>a</div><div>b</div><div>c</div><div>d</div>"
  }),

  // Wildcard style selector: property allowed on every tag via "*".
  "style-wildcard-selector": encodePooledSeed({
    tags: ["div"],
    attrs: ["div|style"],
    styles: ["style|*|color", "style|*|background"],
    html: '<div style="color:red;background:blue;behavior:url(evil)">x</div>'
  }),

  // <style> tag content: selector is matched by string equality against the
  // literal selector text, not real DOM matching (see filterCss).
  "style-tag-selector-text-match": encodePooledSeed({
    tags: ["style", "div"],
    styles: ["style|div|background"],
    html: "<style>div{background:blue;color:red}\ndiv{margin:1px}</style><div>x</div>"
  }),

  // Same string-equality point, but for a class selector: the rule doesn't
  // require any element to actually carry that class.
  "style-class-selector-text-match": encodePooledSeed({
    tags: ["style", "div"],
    styles: ["style|.note|margin"],
    html: '<style>.note{margin:1px;color:red}</style><div class="note">x</div>'
  }),

  // on*/javascript:/data: URLs on several distinct tag+attr combinations at
  // once -- must all be stripped regardless of what the rules allow.
  "dangerous-urls-across-tags": encodePooledSeed({
    tags: ["svg", "form", "object"],
    attrs: ["svg|onload", "form|action", "object|data"],
    html:
      '<svg onload="alert(1)"></svg>' +
      '<form action="javascript:alert(1)"></form>' +
      '<object data="javascript:alert(1)"></object>',
    config: { allowCommonAttributes: false }
  }),

  // srcset with a safe data: image, an unsafe-mimetype data: image, and a
  // javascript: entry in the same attribute value.
  "srcset-mixed-safety": encodePooledSeed({
    tags: ["img"],
    attrs: ["img|srcset"],
    config: { allowDataImageUrls: true },
    html:
      '<img srcset="data:image/png;base64,AAAA 1x, data:image/svg+xml;base64,BBBB 2x, javascript:alert(1) 3x">'
  }),

  // Regression coverage for the constructor/COMMON_ATTRS fix, alongside the
  // vitest regression tests: exercises it through the pooled path with
  // allowCommonAttributes on.
  "prototype-colliding-tag-common-attrs": encodePooledSeed({
    tags: ["constructor", "toString"],
    config: { allowCommonAttributes: true },
    html: '<constructor class="x" id="y"><toString class="z">nested</toString></constructor>'
  })
};

const derivedScenarios = {
  // Prototype-colliding tag AND attribute names together, nested.
  "derived-prototype-colliding-names": encodeDerivedSeed({
    config: { allowCommonAttributes: true },
    html: '<constructor toString="x" data-y="1"><hasOwnProperty>nested</hasOwnProperty></constructor>'
  }),

  // Ambiguous srcset commas with no following whitespace: per the WHATWG
  // grammar these are part of the URL token, not a separator. Regression
  // coverage for the fuzz oracle's own parseSrcsetUrls fix.
  "derived-srcset-ambiguous-commas": encodeDerivedSeed({
    config: { allowDataImageUrls: true },
    html: '<img srcset="1x,data:image/png;base64,AAAA 2x,data:image/svg+xml;base64,BBBB">'
  }),

  // Same ambiguous-comma shape on a non-img tag, where the safe-data-image
  // carve-out never applies (allowSafeDataImage requires tag === "img").
  "derived-srcset-non-img-tag": encodeDerivedSeed({
    config: { allowDataImageUrls: true },
    html: '<b srcset="1x,data:image/svg+xmlz">y</b>'
  }),

  // CSS escape smuggling in inline style, plus an @import in a <style> tag.
  "derived-css-escapes-and-atrules": encodeDerivedSeed({
    html: '<style>div{color:red}@import url(evil.css);</style><div style="behavior:\\75rl(evil)">x</div>'
  }),

  // Quote-bearing form id nested inside svg/template, combining the two
  // known-upstream happy-dom edge cases in one document.
  "derived-nested-form-svg-template": encodeDerivedSeed({
    html: '<form id="&quot;"><template><svg><template>z</template></svg></template></form>'
  })
};

mkdirSync(OUT_DIR, { recursive: true });
const written = [];
for (const [name, bytes] of Object.entries({ ...pooledScenarios, ...derivedScenarios })) {
  const filePath = path.join(OUT_DIR, `generated-${name}`);
  writeFileSync(filePath, bytes);
  written.push(filePath);
}

console.log(`Wrote ${written.length} seeds to ${OUT_DIR}:`);
for (const filePath of written) console.log(`  ${path.basename(filePath)}`);
