import { describe, expect, test } from "vitest";
import { Window } from "happy-dom";
import type { SanitizerWindow } from "../src/core.js";
import { createSanitizer } from "../src/core.js";

// Guard tests for the happy-dom `Node.prototype.nodeName` patch in
// src/core.ts (`ensureSpecCompliantNodeName`). That patch is a workaround for
// a happy-dom quirk that DOMPurify >=3.4.6 trips over: happy-dom's base
// `Node.prototype.nodeName` getter returns "" instead of the tag name, so
// DOMPurify reads every element as nodeName "" and strips it.
//
// A workaround against a peer dependency's internals is a standing liability:
// it can quietly become unnecessary (if happy-dom fixes the quirk) or quietly
// stop working (if the incompatibility changes shape). These two tests make
// both cases fail loudly instead of rotting silently. They deliberately run
// against a FRESH `new Window()` — an isolated realm the sanitizer has not
// patched yet — rather than the global happy-dom DOM the rest of the suite
// (and the patch) has already mutated.

describe("nodeName patch guard", () => {
  test("precondition still holds: happy-dom's base nodeName getter is still broken", () => {
    const win = new Window();
    const nodeProto = (win as unknown as { Node: { prototype: object } }).Node.prototype;
    const baseDesc = Object.getOwnPropertyDescriptor(nodeProto, "nodeName");

    // The patch can only apply if nodeName is a configurable accessor on
    // Node.prototype. If any of these change, the patch's own probe guard
    // (baseDesc?.get / .configurable in core.ts) would silently skip it.
    expect(baseDesc, "happy-dom no longer defines nodeName on Node.prototype").toBeDefined();
    expect(typeof baseDesc?.get, "happy-dom's nodeName is no longer an accessor getter").toBe("function");
    expect(baseDesc?.configurable, "happy-dom's nodeName getter is no longer configurable").toBe(true);

    const el = win.document.createElement("div");
    expect(el.nodeName).toBe("DIV");

    // The heart of the precondition: the base getter disagrees with the real
    // nodeName. When happy-dom fixes this upstream, the two become equal and
    // this assertion fails — that is the signal to DELETE ensureSpecCompliantNodeName
    // from src/core.ts (and this describe block), since it will have become dead code.
    expect(
      baseDesc?.get?.call(el),
      "happy-dom's base Node.prototype.nodeName getter now returns the correct value: " +
        "the quirk is fixed upstream, so ensureSpecCompliantNodeName in src/core.ts is now " +
        "dead code and should be removed."
    ).not.toBe(el.nodeName);
  });

  test("patch is still sufficient: the sanitizer keeps allowed elements on a pristine realm", () => {
    const win = new Window();
    const sanitizer = createSanitizer(win as unknown as SanitizerWindow);

    // Sanitizing drives applyDomPurify -> ensureSpecCompliantNodeName on this
    // fresh realm. Without the patch, DOMPurify would read <p> as nodeName ""
    // and strip it, leaving "".
    const output = sanitizer.sanitize("<p>hi</p>", ["p"]);

    // The patch made the base getter spec-compliant for this realm...
    const el = win.document.createElement("div");
    const patchedDesc = Object.getOwnPropertyDescriptor(
      (win as unknown as { Node: { prototype: object } }).Node.prototype,
      "nodeName"
    );
    expect(
      patchedDesc?.get?.call(el),
      "the sanitizer ran but the base nodeName getter was not corrected: " +
        "ensureSpecCompliantNodeName in src/core.ts is no longer working."
    ).toBe(el.nodeName);

    // ...and DOMPurify consequently preserved the allowed element.
    expect(output).toContain("<p>");
    expect(output).toContain("hi");
  });
});
