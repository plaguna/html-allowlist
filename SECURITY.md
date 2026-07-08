# Security Policy

## Reporting a Vulnerability

Please submit security reports using GitHub Issues for this repository. You can also reach out at plaguna@users.noreply.github.com. We will do our best to respond as soon as possible.

If you want to report them privately, send an email to <mailto:security@appsec.fit>

## Supported versions

Only the latest published version receives security fixes. Fixes are released as patch versions and noted in `CHANGELOG.md`.

## Threat model

`html-allowlist` reduces untrusted HTML to an explicit allowlist. Its output is intended to be safe to insert into a page (`innerHTML` or server-side rendering) when `dangerouslyAllowJavaScript` is `false` (the default).

### What the library defends against

- **Script execution.** `<script>` elements are removed regardless of rules; every element the rules do not allow is removed or unwrapped; DOMPurify runs as a second, independent layer over the final output on every pass.
- **Event-handler injection.** All `on*` attributes are stripped, even when explicitly allowlisted, unless `dangerouslyAllowJavaScript` is `true`.
- **URL scheme smuggling.** `javascript:` and `data:` URLs are removed from all known URL-bearing attributes (`href`, `src`, `xlink:href`, `action`, `formaction`, `poster`, `srcset`, `data`, `background`, and others), including values obfuscated with mixed case, whitespace, control characters, or numeric character references. If `allowDataImageUrls` is enabled, this carve-out is narrow by construction: only `img|src`/`img|srcset`, only a fixed set of raster MIME types, and `image/svg+xml` is excluded unconditionally (it can carry `<script>`/event handlers). `srcset` entries are parsed with a WHATWG-style tokenizer rather than a naive comma split, since a `data:` URI's own header/payload comma would otherwise be misread as an entry separator.
- **CSS-based execution and exfiltration.** All at-rules (including `@import`) are removed. Declarations whose values use `url()`, `image()`, `image-set()`, `expression()`, `element()`, `attr()`, or their vendor-prefixed variants are removed. CSS escape sequences in those function names (e.g. `\75rl(...)`, `\75 rl(...)`, `\65xpression(...)`, which browsers decode to `url(...)`/`expression(...)`) are decoded before the check, so an escaped spelling cannot slip past it. The legacy `behavior` and `-moz-binding` properties are removed even if explicitly allowlisted. Only selector/property pairs named by `style|selector|property` rules survive.
- **Mutation XSS (mXSS) and namespace confusion.** The sanitizer works on a parsed DOM (never regex over strings), re-runs until output reaches a fixed point, and finishes each pass with DOMPurify, which carries its own mXSS hardening. If output does not converge within `maxPasses`, the sanitizer throws `ConvergenceError` instead of returning a result it had not finished transforming.
- **Inert `<template>` content.** A template's parsed children live in a separate `.content` document fragment rather than among its child nodes. The allowlist pass descends into that fragment, so content inside an allowlisted `<template>` is filtered identically to the rest of the document (rather than being left to DOMPurify alone) — important because it becomes live the moment a script clones it into the document.
- **DOM clobbering of the sanitizer itself.** DOMPurify's clobbering protections apply to the output; the sanitizer does not read attributes through clobberable DOM lookups.
- **Policy typos.** Malformed rules throw `RuleSyntaxError` at compile time instead of being silently ignored, so a mistyped rule cannot quietly weaken a policy.

### What the library does not defend against

- **Everything allowed by your rules.** The allowlist is the policy: if you allow `iframe` or set `dangerouslyAllowJavaScript: true` with script rules, the output can do what those features do. `dangerouslyAllowJavaScript` in particular turns off two of the default safety nets — `on*` stripping and `<script>` removal — so scripts and event handlers survive wherever your rules admit them (DOMPurify still blocks `javascript:`/`data:` URLs either way). Review any call that sets it as security-sensitive configuration.
- **CSS side channels beyond fetch/script functions.** Layout-based information leaks through allowed properties are out of scope.
- **Phishing and content spoofing.** Allowed markup can still display misleading text or links with safe schemes (`https:` URLs are not reputation-checked).
- **Resource loading from allowed URLs.** A permitted `img|src` with an `https:` URL loads that resource; use CSP to constrain origins.
- **Non-HTML contexts.** Output is safe for HTML element context, not for insertion into attribute values, `<script>` bodies, URLs, or CSS strings.

### Defense in depth

The DOM-based allowlist pass and DOMPurify run in series on every pass, so a bypass must defeat both layers. A CI job continuously tests against the newest `dompurify` and `happy-dom` releases to catch upstream behavior changes before they reach users. The test suite includes an XSS vector corpus, real-world fixture documents, property-based idempotence tests, and node/browser parity tests.

We recommend serving sanitized content with a Content Security Policy as an additional layer.
