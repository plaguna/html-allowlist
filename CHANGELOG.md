# Changelog

## 1.1.0 — 2026-10-24

### Security

- Raised the minimum runtime dependency versions so installs can no longer
  resolve releases with known advisories:
  - `dompurify` `^3.4.11` → `^3.4.17`, past
    [GHSA-p98j-92pf-mc4p](https://github.com/advisories/GHSA-p98j-92pf-mc4p)
    (low; detached subtrees keeping event handlers when an `afterSanitize`
    hook removes nodes under `IN_PLACE`).
  - `postcss` `^8.4.47` → `^8.5.31`, which requires `source-map-js`
    `^1.2.2`, past
    [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q)
    (high; event-loop DoS via indexed source-map section offsets).

  Neither is reachable through html-allowlist itself: the sanitizer does not
  use DOMPurify's `IN_PLACE` mode or hooks, and never parses source maps.
  The floors are raised so dependency scanners stay clean and so a
  consumer's lockfile can't pin the vulnerable versions underneath us.
- Dev-only advisories cleared: `happy-dom` 20.11.2 → 21.0.4 (upstream code
  injection, SSRF and cookie-scope fixes), `browserslist` 4.28.5 → 4.28.9,
  `baseline-browser-mapping`, `vite` 8.2.2 → 8.3.5, `vitest` 4.1.11 →
  4.1.12 (`@vitest/mocker` advisories), and `tar`. `npm audit` reports 0
  vulnerabilities.

No behavior changes to the sanitizer. The `happy-dom` peer range
(`>=20.0.0`) is unchanged; the test suite now runs against 21.x.

## 1.0.2 — 2026-08-26

### Maintenance

- Routine dependency updates: `dompurify` 3.4.11 → 3.4.14, `postcss` 8.5.16 →
  8.5.26, `happy-dom` 20.10.6 → 20.11.2, `typescript` 6.0.2 → 7.0.2,
  `@types/node` 25.5.0 → 26.2.0, `vitest` 4.1.0 → 4.1.11, `fast-check` 4.6.0
  → 4.9.0, plus the npm_and_yarn group and `actions/checkout` CI bumps. No
  behavior changes to the sanitizer itself; `dompurify` and `postcss` stayed
  within their existing declared `^` ranges.

## 1.0.1 — 2026-07-09

### Security

- `filterAttributes` looked up `allowCommonAttributes` defaults with a plain
  object keyed by tag name (`COMMON_ATTRS[tag]`). For a tag name matching an
  inherited `Object.prototype` property -- `constructor`, `toString`,
  `valueOf`, `hasOwnProperty`, and others -- the lookup returned that
  inherited value (e.g. the `Object` constructor function) instead of
  `undefined`, and the subsequent `for...of` over it threw `TypeError:
  ... is not iterable`. Reachable as a denial-of-service on any caller with
  `allowCommonAttributes: true` and a policy allowing such a tag, triggered
  purely by attacker-controlled HTML content (e.g. `<constructor>`).
  `COMMON_ATTRS` is now a `Map`, consistent with the rest of the compiled
  policy's internals. Found by the fuzz target's new document-derived rule
  mode (see `fuzz/sanitize.fuzz.js`), which builds rules directly from
  mutator-produced HTML instead of a small fixed pool.
- `isDangerousUrl` checked `javascript:` and `data:` but not `vbscript:`,
  relying on DOMPurify's default scheme regex to reject it incidentally.
  That held for a single-candidate `srcset` value, but a malformed
  multi-candidate one let a `vbscript:` entry through DOMPurify's own
  `srcset` validation while an otherwise-identical `javascript:` entry in
  the same shape was still caught -- so the backstop wasn't reliable.
  `vbscript:` is IE-only and long dead, but the check is free and now runs
  in our own pre-filter instead of depending on DOMPurify's incidental
  behavior. Found by the fuzz target using a hand-crafted seed
  (`fuzz/generate-corpus.js`) exercising a mixed-safety `srcset` value.

## 1.0.0 — 2026-07-08

First stable release. The rule language (multiset tag counts, `tag|attr`,
`style|selector|property`) and the public API are now covered by semantic
versioning.

### Security

- The CSS value filter now decodes CSS escape sequences before checking for
  dangerous functions. Browsers read `\75rl(...)`, `u\72l(...)`, and
  `\75 rl(...)` (a trailing space terminates a hex escape) all as `url(...)`,
  and `\65xpression(...)` as `expression(...)`; postcss-value-parser preserves
  the backslashes verbatim, so previously an escaped spelling of a fetch- or
  script-capable function could survive in an allowlisted declaration and
  execute/fetch once a browser decoded it. Escapes are now resolved on the
  whole value first, so every spelling collapses to its canonical name before
  the check.
- The allowlist pass now descends into `<template>` content. A template's
  parsed children live in a separate inert `.content` document fragment that a
  normal DOM walk does not reach, so previously everything inside a `<template>`
  (when the tag was allowlisted) skipped tag-count, per-tag attribute, URL, and
  CSS filtering and was left to DOMPurify alone. With `allowDataImageUrls`
  enabled that was exploitable: DOMPurify's URI filter is deliberately widened
  to trust our own pre-filter, which never ran inside the template, so a
  `data:image/svg+xml,<svg onload=...>` payload could survive into the output
  and execute once a client script cloned the template content into the live
  DOM. Template content is now filtered exactly like the rest of the document.
- The CSS filter now removes declarations whose values use `image()`,
  `image-set()`, `-webkit-image-set()`, `expression()`, `element()`,
  `-moz-element()`, or `attr()` in addition to `url()`. Previously an
  allowlisted property could carry `expression(...)` (legacy IE script
  execution) or fetch-capable functions other than `url()`.
- The legacy `behavior` and `-moz-binding` CSS properties are removed even
  when explicitly allowlisted.

### Changed (breaking)

- `sanitize` and `sanitizeWithPolicy` now return a body fragment by default
  (no `<html>`/`<head>`/`<body>` wrapper). Pass
  `{ outputFormat: "document" }` for the previous full-document output.
  Content that ends up inside `<head>` (e.g. a `<link>` explicitly nested in
  a `<head>...</head>` block) is discarded in fragment mode, since it never
  reaches `<body>`.
- `compileRules` and `sanitize` now throw `RuleSyntaxError` on malformed
  rules (empty segments, more than three segments, three-segment rules not
  starting with `style`, whitespace inside tag/attribute names). Previously
  malformed rules were silently ignored, which could weaken a policy without
  warning.
- `CompiledPolicy` is now an opaque type; its internal layout is no longer
  part of the public API. `sanitizeWithPolicy` throws `TypeError` when given
  an object that did not come from `compileRules`.
- `sanitize` and `sanitizeWithPolicy` now throw the new `ConvergenceError`
  when the output does not reach a fixed point within `maxPasses`. Previously
  they silently returned the last (unconverged) pass — output the sanitizer
  had not finished transforming. Note this makes `maxPasses` values below `2`
  always throw for input that needs cleaning (one pass to clean, one to
  confirm); the default of `10` is unaffected.
- The `allowJavaScript` config option is renamed to
  `dangerouslyAllowJavaScript`. Behavior is unchanged, but the name now makes
  the escape hatch self-documenting at the call site: enabling it turns off
  the `on*`-stripping and `<script>`-removal safety nets, so scripts and event
  handlers survive wherever the allowlist rules admit them (DOMPurify still
  blocks `javascript:`/`data:` URLs regardless). The old name is not accepted.
- Node.js 18 and 20 are no longer supported (both are end-of-life); the
  minimum is now Node.js 22.12.
- `happy-dom` is now a peer dependency (`peerDependenciesMeta.optional: true`)
  instead of a regular dependency, and is loaded lazily via
  `createRequire(...).require("happy-dom")` only when no
  `globalThis.DOMParser`/`globalThis.window` is available. Browser-only
  consumers no longer pull in `happy-dom` on `npm install`. Node consumers
  without a native DOM must run `npm install happy-dom` alongside
  `html-allowlist`; calling `sanitize` without it throws an error naming the
  missing dependency.

### Added

- `allowDataImageUrls` config option: when enabled (and
  `dangerouslyAllowJavaScript` is `false`), allows `data:` URLs on `img|src`
  and `img|srcset` if their
  declared MIME type is a safe raster image type (png, jpeg, gif, webp, bmp,
  x-icon, avif). `image/svg+xml` is excluded unconditionally, even if
  requested, since it can carry `<script>`/event handlers. All other tags
  and attributes keep blocking `data:` URLs regardless of this option.
- `createSanitizer(window)` export: bring your own DOM. Returns
  `{ sanitize, sanitizeWithPolicy }` bound to a `window` you supply (a browser,
  jsdom, linkedom, or self-configured happy-dom window), so you can avoid the
  `happy-dom` peer dependency (and its Node floor) or insulate yourself from
  any single DOM implementation. Nothing in this path loads `happy-dom`. New
  `Sanitizer` and `SanitizerWindow` types accompany it.
- `RuleSyntaxError` export with the offending rule on `error.rule`.
- `ConvergenceError` export with the attempted pass budget on `error.passes`.
- XSS vector corpus tests, node/browser entry parity tests, and rule
  validation tests.
- A CI job that runs the suite against the newest `dompurify` and
  `happy-dom` releases (plus a weekly scheduled run) to catch upstream
  changes early.
- A threat model in `SECURITY.md`.

### Internal

- The node and browser entry points now share a single sanitizer core
  (`src/core.ts`); the entries only provide DOM environment glue. This
  removes ~400 lines of duplicated security-critical code that had already
  started to drift.
- `srcset` values are now parsed with a small WHATWG-style tokenizer instead
  of a naive `value.split(",")`, since a URL can itself contain a comma
  (most notably a `data:` URI's own header/payload separator), which the
  naive split would cut in half. This was previously a latent
  over-blocking-only issue (a truncated `data:`/`javascript:` fragment always
  keeps its dangerous prefix intact, so nothing unsafe could slip through);
  it became a real functionality bug once `data:` URLs needed to survive in
  `srcset` for `allowDataImageUrls`.

### Docs

- The rule language's semantics (multiset tag counts, `tag|attr`,
  `style|selector|property`) are now documented as stable as of 1.0. In
  particular, the multiset behavior of tag rules (repeat a tag name to raise
  its allowed count) is confirmed intentional, not an accident of an early
  implementation, and will not change in a future 1.x release.

## 0.1.1 — 2026-07-03

### Fixed

- Compatibility with DOMPurify ≥ 3.4.6 on happy-dom. DOMPurify's
  anti-clobbering hardening reads `nodeName` through a getter cached from
  `Node.prototype`; happy-dom's base getter returns `""` (subclasses shadow
  it), so every element was misidentified as disallowed — allowed content was
  stripped and DOMPurify's child hoisting crashed with
  `Failed to execute 'insertBefore' on 'Node': Only one element on document allowed.`
  The sanitizer now makes the base `Node.prototype.nodeName` getter
  spec-compliant (delegating to the instance's most-derived getter, matching
  browser behavior) on the window handed to DOMPurify. The patch is
  probe-guarded, idempotent, and does not change normal property access.

### Changed

- Raised dependency floors to the versions the fix is tested against:
  `dompurify@^3.4.11`, `happy-dom@^20.10.6`.

## 0.1.0

Initial release.
