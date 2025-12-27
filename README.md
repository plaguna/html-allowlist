# html-allowlist

A tiny HTML sanitizer that reduces markup to a constrained subset defined by a rule list. The sanitizer applies rules recursively until output converges.

## AI-assisted project notice

This project was created with the assistance of AI tools. Contributions and review are welcome to validate behavior, security posture, and documentation.

## Install

```bash
npm install html-allowlist
```

## Module format

This package is ESM-only.

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

## API

### `sanitize(html, rules, config?)`

```ts
sanitize(html: string, rules: string[], config?: SanitizerConfig): string
```

Returns a cleaned HTML document string (including `<html>`, `<head>`, and `<body>`). The sanitizer runs multiple passes until the output stops changing or a maximum pass count is reached.

### `compileRules(rules, config?)`

```ts
compileRules(rules: string[], config?: SanitizerConfig): CompiledPolicy
```

Parses and normalizes rules once, returning a reusable policy object.

### `sanitizeWithPolicy(html, policy)`

```ts
sanitizeWithPolicy(html: string, policy: CompiledPolicy): string
```

Sanitizes using a precompiled policy. Output matches `sanitize` for the same rules and config.

### `SanitizerConfig`

- `allowCommonAttributes?: boolean` (default: `false`)
  - Allows conservative default attributes for some tags plus global `class`/`id`.
- `allowJavaScript?: boolean` (default: `false`)
  - When `false`, removes `on*` attributes and blocks `javascript:` and `data:` URLs.
  - When `true`, script-related constructs still require explicit rules.
- `maxPasses?: number` (default: `10`)
  - Maximum number of recursive passes before stopping.

### `CompiledPolicy`

An internal policy shape produced by `compileRules` and consumed by `sanitizeWithPolicy`. It is deterministic and safe to reuse across calls for the same rules and config.

## Rule language

Rules are strings; duplicates are meaningful.

### 1) Allowed tags (multiset semantics)

A bare tag name allows that tag a limited number of times.

Examples:
- `"a"` allows **at most 1** `<a>` element.
- `"a", "a"` allows **at most 2** `<a>` elements.

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

`<style>` tags are removed unless the `style` tag is allowed **and** at least one `style|...|...` rule exists. Declarations not matching allowed selector/property pairs are removed. The CSS filter parses styles and removes all at-rules (including `@import`) and any declarations that use `url()`.

Inline `style` attributes are filtered using the same allowlist. To keep any inline styles, the tag must allow the `style` attribute (e.g. `p|style`) and there must be a matching style rule using either `style|*|prop` or `style|tag|prop`. Declarations that are not allowlisted are removed, and the attribute is dropped if nothing remains.

## Defaults and security posture

- `allowJavaScript` defaults to `false`.
- Event handlers (`on*`) are stripped when `allowJavaScript` is `false`.
- `javascript:` and `data:` URLs are removed from `href`, `src`, `xlink:href`, `action`, `formaction`, `poster`, and `srcset` when `allowJavaScript` is `false`.
- `<script>` tags are removed when `allowJavaScript` is `false`.
- Output is always sanitized by DOMPurify using the configured allowlist to mitigate XSS in both browser and Node environments. When `allowJavaScript` is `true`, scripts and script-related attributes still require explicit rules to be preserved.

## Development

```bash
npm test
```

## Security

See `SECURITY.md` for reporting guidance and supported versions.

## License

MIT
