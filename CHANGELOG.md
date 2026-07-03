# Changelog

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
