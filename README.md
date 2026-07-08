# html-allowlist

A tiny HTML sanitizer that reduces markup to a constrained subset defined by a rule list. The sanitizer applies rules recursively until output converges.

## AI-assisted project notice

This project was created with the assistance of AI tools. Contributions and review are welcome to validate behavior, security posture, and documentation.

## Install

```bash
npm install html-allowlist
```

## Module format

This package is ESM-only and requires Node.js 22.12 or newer (or a browser environment).

### Node.js: install happy-dom too

Node has no built-in `DOMParser`, so the Node entry point needs a DOM implementation. `happy-dom` is a peer dependency, not a regular dependency, so browser-only consumers don't have to install it:

```bash
npm install html-allowlist happy-dom
```

If `globalThis.DOMParser` and `globalThis.window` are already provided by your runtime (for example inside a test environment that sets up its own DOM globals), `happy-dom` is not needed and `sanitize` uses those globals directly. Otherwise, calling `sanitize` without `happy-dom` installed throws an error telling you to install it.

Browser usage (via the `browser` export condition) never touches `happy-dom`.

If you would rather not depend on `happy-dom` at all — or want to run on a DOM implementation you control — use [`createSanitizer`](#createsanitizerwindow) to bring your own.

## Usage

```ts
import { sanitize } from "html-allowlist";

const html = "<p><a href=\"https://example.com\">ok</a><a>nope</a></p>";
const rules = ["p", "a", "a|href"];

const output = sanitize(html, rules, { allowCommonAttributes: true });
```

If you sanitize repeatedly with the same rules, compile them once:

```ts
import { compileRules, sanitizeWithPolicy } from "html-allowlist";

const policy = compileRules(rules, { allowCommonAttributes: true });
const output = sanitizeWithPolicy(html, policy);
```

### Bring your own DOM

The default `sanitize`/`sanitizeWithPolicy` exports rely on `happy-dom` in Node (or your runtime's DOM globals). If you would rather run on a DOM implementation you control — a browser `window`, [jsdom](https://github.com/jsdom/jsdom), [linkedom](https://github.com/WebReflection/linkedom), or a `happy-dom` `Window` you configured yourself — pass it to `createSanitizer`:

```ts
import { JSDOM } from "jsdom";
import { createSanitizer } from "html-allowlist";

const { window } = new JSDOM("");
const { sanitize, sanitizeWithPolicy } = createSanitizer(window);

const output = sanitize(html, rules, { allowCommonAttributes: true });
```

Nothing in this path loads `happy-dom`; the sanitizer uses only the `window` you supply. This is the recommended way to avoid the `happy-dom` peer dependency (and its Node version floor) entirely, or to insulate yourself from upstream changes in any single DOM implementation.

## API

### `sanitize(html, rules, config?)`

```ts
sanitize(html: string, rules: string[], config?: SanitizerConfig): string
```

Returns cleaned HTML. By default this is a body fragment (see `outputFormat` below); pass `{ outputFormat: "document" }` for a full `<html><head><body>` document. The sanitizer runs multiple passes until the output stops changing or a maximum pass count is reached.

### `compileRules(rules, config?)`

```ts
compileRules(rules: string[], config?: SanitizerConfig): CompiledPolicy
```

Parses and normalizes rules once, returning a reusable policy object. Throws `RuleSyntaxError` if any rule is malformed (empty segments, more than three segments, a three-segment rule that does not start with `style`, or whitespace inside tag/attribute names). `sanitize` applies the same validation.

### `sanitizeWithPolicy(html, policy)`

```ts
sanitizeWithPolicy(html: string, policy: CompiledPolicy): string
```

Sanitizes using a precompiled policy. Output matches `sanitize` for the same rules and config. Throws `TypeError` if `policy` was not created by `compileRules`.

### `createSanitizer(window)`

```ts
createSanitizer(window: SanitizerWindow): Sanitizer
```

Returns `{ sanitize, sanitizeWithPolicy }` bound to a DOM `window` you supply, deriving the HTML parser from `window.DOMParser` and initializing DOMPurify against `window`. The returned functions have the same signatures and behavior as the package-level exports of the same names. Use this to bring your own DOM (see [Bring your own DOM](#bring-your-own-dom)) instead of relying on the Node entry's bundled `happy-dom` fallback.

`SanitizerWindow` is any DOM `Window` that provides a `DOMParser` and the standard constructors DOMPurify needs (`Node`, `Element`, `DocumentFragment`, `HTMLTemplateElement`, `NodeFilter`, `NamedNodeMap`, `HTMLFormElement`); a browser, jsdom, linkedom, or happy-dom window all qualify. Depending on your DOM library's TypeScript types you may need a cast (e.g. `createSanitizer(window as unknown as SanitizerWindow)`), the same as when initializing DOMPurify directly.

### `RuleSyntaxError`

Thrown by `compileRules` (and `sanitize`) when a rule is malformed. Exposes the offending rule string as `error.rule`. Rules are validated strictly so a typo in a security policy fails loudly instead of being silently ignored.

### `ConvergenceError`

Thrown by `sanitize` and `sanitizeWithPolicy` when the output does not reach a fixed point within `maxPasses` (see [`maxPasses`](#sanitizerconfig)). Exposes the attempted pass budget as `error.passes`. Rather than returning a partially-sanitized result the sanitizer had not finished transforming — which for adversarial input could still be mid-mutation — it fails loudly so you can investigate the input or raise `maxPasses`.

### `SanitizerConfig`

- `allowCommonAttributes?: boolean` (default: `false`)
  - Allows conservative default attributes for some tags plus global `class`/`id`.
- `dangerouslyAllowJavaScript?: boolean` (default: `false`)
  - **Escape hatch — enable only if you fully trust your own rules.** When `false` (the default), the sanitizer applies JavaScript safety nets on top of your rules: `on*` attributes are stripped, `<script>` is removed, and the library's own `javascript:`/`data:` URL pre-filter runs.
  - When `true`, the `on*` and `<script>` safety nets are turned off and **the allowlist rules carry the policy.** A `<script>` or an `on*` handler then survives if (and only if) your rules explicitly permit the tag/attribute carrying it — so enabling this can allow script execution. It does **not** blanket-allow JavaScript, and it does **not** re-open `javascript:`/`data:` URLs on its own: DOMPurify still runs as an independent second layer and blocks those schemes regardless of this option. Because the default belt-and-suspenders are gone, a permissive rule set can still produce output that is no longer safe to `innerHTML`. The `dangerously` prefix is deliberate; treat any call that sets this as security-sensitive.
- `allowDataImageUrls?: boolean` (default: `false`)
  - When `true` (and `dangerouslyAllowJavaScript` is `false`), allows `data:` URLs on `img|src` and `img|srcset` if their declared MIME type is a safe raster image type: `image/png`, `image/jpeg`, `image/gif`, `image/webp`, `image/bmp`, `image/x-icon`, `image/vnd.microsoft.icon`, or `image/avif`.
  - `image/svg+xml` is never allowed through a `data:` URL, even if requested — SVG can carry `<script>` and event handler attributes, so treating it as a safe image would reopen the vector this option exists to keep closed.
  - The MIME type is trusted as declared; it is not verified against the actual decoded bytes (this matches how `<img>` itself treats `data:` URLs — the image decoder either renders valid bytes for the claimed type or fails to render, it never executes them as script or HTML).
  - `data:` URLs on any other tag or attribute (`a|href`, `background`, etc.) remain blocked regardless of this option.
  - Has no effect when `dangerouslyAllowJavaScript` is `true`: in that mode the library's `data:` pre-filter does not run and DOMPurify's default URI allowlist (which excludes `data:`) is left in place, so `data:` image URLs are blocked.
- `maxPasses?: number` (default: `10`)
  - Maximum number of recursive passes. The sanitizer re-runs over its own output until the result stops changing (reaches a fixed point). If it does not converge within `maxPasses`, it throws [`ConvergenceError`](#convergenceerror) rather than returning output it had not finished transforming.
  - Because confirming a fixed point takes one pass to transform and another to observe no change, values below `2` can never converge for input that needs cleaning and always throw. The default of `10` leaves ample room; raise it only if you have input that legitimately needs more passes.
- `outputFormat?: "document" | "fragment"` (default: `"fragment"`)
  - `"fragment"` returns the contents of `<body>` only, with no `<html>`/`<head>`/`<body>` wrapper. Any input content that ends up inside `<head>` (for example, a `<link>` or `<meta>` explicitly nested in a `<head>...</head>` block) is discarded, since it never reaches `<body>`.
  - `"document"` returns the full parsed document, including `<html>`, `<head>`, and `<body>`.

### `CompiledPolicy`

An opaque handle produced by `compileRules` and consumed by `sanitizeWithPolicy`. Its internal layout is not part of the public API. It is deterministic and safe to reuse across calls for the same rules and config.

## Rule language

Rules are strings; duplicates are meaningful. The rule language's semantics below (multiset tag counts, `tag|attr` attribute allowlisting, `style|selector|property` CSS scoping) are stable as of 1.0: a policy that compiles and behaves a certain way today will keep compiling and behaving the same way in future 1.x releases. Changing them is reserved for a major version bump.

### 1) Allowed tags (multiset semantics)

A bare tag name allows that tag a limited number of times, counted globally across the whole document (not per parent element).

Examples:
- `"a"` allows **at most 1** `<a>` element.
- `"a", "a"` allows **at most 2** `<a>` elements.

This multiset behavior — repeat a tag name to raise its count — is intentional and will not change: it is the only way the rule language expresses "how many," so it has to stay put for existing policies to keep meaning what they meant when they were written.

Matching is case-insensitive. Canonical form is lowercase.

### 2) Allowed tag attributes

Format:
- `tag|attr`

Examples:
- `"a|href"` allows `<a href="...">`.
- `"html|lang"` allows `<html lang="...">`.

Attributes are only kept if the tag is allowed and the attribute is explicitly allowed (or permitted by `allowCommonAttributes`).

### allowCommonAttributes defaults

When enabled, the sanitizer allows a conservative set of attributes without extra rules:

- Global: `class`, `id`
- `a`: `href`, `title`, `target`, `rel`
- `img`: `src`, `alt`, `title`, `width`, `height`
- `html`: `lang`

### 3) Allowed `<style>` declarations scoped to a selector or tag

Format:
- `style|<selectorOrTag>|<cssProperty>`

Examples:
- `"style|.header|margin"`
- `"style|div|background-color"`

`<style>` tags are removed unless the `style` tag is allowed **and** at least one `style|...|...` rule exists. Declarations not matching allowed selector/property pairs are removed. The CSS filter parses styles and removes all at-rules (including `@import`), any declarations whose values use fetch- or script-capable functions (`url()`, `image-set()`, `expression()`, `element()`, `attr()`, and vendor-prefixed variants), and the legacy `behavior`/`-moz-binding` properties even if explicitly allowlisted.

Inline `style` attributes are filtered using the same allowlist. To keep any inline styles, the tag must allow the `style` attribute (e.g. `p|style`) and there must be a matching style rule using either `style|*|prop` or `style|tag|prop`. Declarations that are not allowlisted are removed, and the attribute is dropped if nothing remains.

## Defaults and security posture

- `dangerouslyAllowJavaScript` defaults to `false`.
- Event handlers (`on*`) are stripped when `dangerouslyAllowJavaScript` is `false`.
- `<script>` tags are removed when `dangerouslyAllowJavaScript` is `false`.
- `javascript:` and `data:` URLs are removed from `href`, `src`, `xlink:href`, `action`, `formaction`, `poster`, `srcset`, and the other URL-bearing attributes — by the library's own pre-filter when `dangerouslyAllowJavaScript` is `false`, and by DOMPurify's URI allowlist even when it is `true`. The one carve-out is `allowDataImageUrls`, which lets a specific safe-mimetype `data:` value through on `img|src`/`img|srcset` (see `SanitizerConfig` above).
- Output is always sanitized by DOMPurify using the configured allowlist to mitigate XSS in both browser and Node environments. Setting `dangerouslyAllowJavaScript: true` turns off the `on*` and `<script>` safety nets (they then survive where your rules allow them) but does not disable this DOMPurify pass.

## Development

```bash
npm test
```

## Security

See `SECURITY.md` for reporting guidance and supported versions.

## License

MIT
