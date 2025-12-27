# AGENTS.md — html-allowlist

This repository contains `html-allowlist`, a TypeScript library (browser + Node.js) that reduces HTML to a constrained subset defined by a rule list. The library applies rules recursively until all constraints are satisfied.

This file defines how contributors and automation agents must work in this codebase.

---

## Non-negotiable workflow

### Test-driven development only
1. **Write tests first** that specify the intended behavior.
2. Run tests and ensure they fail for the right reason.
3. Implement the smallest change to make tests pass.
4. Refactor only after green tests.

No feature work is accepted without tests.

### Deterministic and idempotent
- Given identical input and configuration, output must be identical.
- Running the sanitizer multiple times should converge quickly and remain stable (idempotent once compliant).

---

## Scope decisions (project constraints)

- Tag count rules are enforced **per document** (global count across the full HTML).
- Attribute value constraints are **not supported** (allow/deny is by attribute presence only).
- CSS value allowlisting is **not supported** (CSS allow/deny is by selector + property only).

## Core concepts

### Inputs
- `html: string`
- `rules: string[]` — a multiset (duplicates matter)
- `config?: SanitizerConfig`

### Output
- A cleaned HTML string that:
  - Contains only constructs allowed by the rules + config.
  - Contains no disallowed attributes, tags, or CSS declarations.
  - Converges via recursive passes until no further changes are necessary (or a maximum pass count is reached).

---

## Rule language

Rules are strings; duplicates are meaningful.

### 1) Allowed tags (multiset semantics)
A bare tag name allows that tag a limited number of times.

Example:
- Rules: `["a"]` allows **at most 1** `<a>` element.
- Rules: `["a", "a"]` allows **at most 2** `<a>` elements.

Case-insensitive matching. Canonical form is lowercase.

### 2) Allowed tag attributes
Format:
- `tag|attr`
- `tag|attr1,attr2` (if implemented) OR multiple rules `tag|attr1`, `tag|attr2`

Examples:
- `a|style` allows `<a style="...">`
- `html|lang` allows `<html lang="...">`

Attribute allowlisting is additive with tag allowlisting:
- A tag must be allowed by tag rules (counted).
- Attributes must be allowed either explicitly by rule or via `allowCommonAttributes`.

### 3) Allowed `<style>` declarations scoped to a selector or tag
Format:
- `style|<selectorOrTag>|<cssProperty>`

Rules for this format:
- The first segment must be exactly `style`.
- The second segment is a **selector or tag** such as:
  - `div`
  - `.header`
  - `.container`
  - `#main` (if supported)
- The third segment is a CSS property name, such as `background-color`, `margin`, `display`.

Example:
- `style|.header|margin` allows `<style>` rules that set `margin` for `.header`.
- `style|div|background-color` allows setting `background-color` for `div`.

Notes:
- Only CSS properties explicitly allowed by these rules are permitted within `<style>`.
- Declarations not matching the allowed selector+property pairs must be removed.
- The library must not allow CSS constructs that can lead to script execution or network exfiltration unless explicitly enabled (see Security).

---

## Configuration

### `allowCommonAttributes: boolean`
If enabled, allow a conservative set of “common attributes” for specific tags (examples):
- `a`: `href`, `title`, `target`, `rel`
- `img` (if ever allowed): `src`, `alt`, `title`, `width`, `height`
- `html`: `lang`
- `*`: `class`, `id` (optional; if enabled, must be documented and tested)

This setting **does not** bypass tag-count rules. It only affects attribute filtering.

### `allowJavaScript: boolean`
If enabled:
- JavaScript-capable attributes/tags may be considered, but **still require explicit rules** (e.g., `script` tag must be present in rules to allow `<script>`, and event attributes like `onmouseover` must be explicitly allowed via rules if supported).
- The library must apply an XSS mitigation layer (e.g., DOMPurify or equivalent strategy) such that output is safe against common XSS vectors when `allowJavaScript` is false, and remains controlled when true.

If `allowJavaScript` is false:
- Remove all event handler attributes (`on*`).
- Remove/neutralize `javascript:` URLs.
- Strip `<script>` and other script-executing tags regardless of tag-count rules unless explicitly allowed by both config and rules (implementation-defined but must be consistent and tested).

---

## Cleaning algorithm requirements

### Parse → Transform → Serialize
- Always parse HTML into a DOM-like structure (real DOM in browser, JSDOM/linkedom/happy-dom or equivalent in Node).
- Perform transformations on nodes and attributes, not with regex substitutions.
- Serialize back to HTML.

### Recursive passes until fixed point
The sanitizer must run multiple passes until:
- No changes occur between passes, OR
- A maximum pass count is reached (to prevent infinite loops).

Each pass must:
1. Enforce allowed tag counts (multiset):
   - Keep earliest occurrences in document order by default.
   - Remove extra occurrences beyond allowed counts.
2. Enforce attribute allowlist:
   - Remove disallowed attributes.
   - For allowed attributes, normalize values if required (e.g., trimming, dropping invalid URLs).
3. Enforce `<style>` constraints:
   - Remove `<style>` entirely unless allowed by rules (either by allowing `style` tag count and at least one `style|...|...` rule exists).
   - If allowed, parse CSS and remove disallowed selectors/properties/declarations.
4. Enforce JavaScript policy:
   - Apply DOMPurify (or equivalent) when configured, consistent across environments.

### Convergence
- Must converge in a small number of passes for typical inputs.
- Must expose debug information in tests (optional) but output must remain stable.

---

## Testing requirements

### Test suite characteristics
- Tests must cover both Node and browser-equivalent environments (at least via a DOM shim).
- Use golden tests for complex HTML cases (input → expected output).
- Include property-like tests for idempotence:
  - `sanitize(sanitize(html)) === sanitize(html)`
- Include tests for recursion/fixed-point behavior:
  - Confirm multiple passes occur when needed.
  - Confirm termination at max passes.

### Mandatory test categories
1. **Tag count enforcement**
   - Duplicate rules increase allowed occurrences.
   - Excess tags removed deterministically.
2. **Attribute allowlisting**
   - `tag|attr` works.
   - `allowCommonAttributes` adds expected attrs only.
3. **Style rules**
   - `style|selector|property` allows matching declarations only.
   - Disallowed declarations removed.
   - Style tag removed when not allowed.
4. **JavaScript/XSS**
   - `allowJavaScript: false` strips event handlers and `javascript:` URLs.
   - `allowJavaScript: true` requires explicit rules to permit script-related constructs.
5. **Normalization**
   - Canonical lowercase tags/attrs in rule matching.
   - Output formatting is stable enough for snapshot/golden tests.

---

## Examples (rule behavior)

Given rules:
```ts
["a", "a", "p|display", "style|.header|margin", "br", "html"]
```

Expected implications:

- Up to 2 <a> tags total are permitted.
- <p> may only keep attribute display if present (unless common attributes config expands).
- <style> may exist only if style is allowed as a tag (counted) AND CSS is restricted to:
  - selector .header
  - property margin
- <br> allowed once.
- <html> allowed once, with optional lang if allowCommonAttributes is enabled.

## Security posture

### Default mode (recommended)

- allowJavaScript defaults to false.
- Remove:
  - <script>, <iframe>, <object>, <embed> (unless explicitly enabled by config+rules)
  - event handler attributes (on*)
  - javascript: URLs
- CSS must be parsed and constrained by allowlist rules.

### Explicitly permissive mode

When allowJavaScript: true:

- Any JavaScript-capable feature still requires explicit rules.
- Sanitization must remain deterministic and test-covered.
- “Best effort” is not acceptable: behavior must be specified by tests.

## Public API expectations (to be implemented under tests)

The API should remain small and stable.

Suggested surface:

```sanitize(html: string, rules: string[], config?: SanitizerConfig): string```

Optional:

```compileRules(rules: string[], config?: SanitizerConfig): CompiledPolicy```

```sanitizeWithPolicy(html: string, policy: CompiledPolicy): string```

If a compile step is added, ensure it is pure and serializable where practical.

## Contribution rules

- No change without tests.
- No new rule syntax without:
  - parser tests
  - semantic tests
  - security tests (if it touches JS/CSS/URLs)

Keep runtime dependencies minimal and compatible with both browser and Node.

## Repository standards

- TypeScript strict mode enabled.
- Linting/formatting is enforced in CI.
- All rules and config defaults must be documented in README.md.
- Any environment-specific behavior must be tested and documented.


**Q1:** Should tag-count rules apply per document, per parent node, or per selector (e.g., “one `<a>` per `<p>`”)?  
**Q2:** Do you want rule support for attribute value constraints (e.g., `a|href:https`, `img|src:relative-only`)?  
**Q3:** Should CSS values be allowlisted too (e.g., only `margin: 0`), or only selector+property filtering is enough?**
