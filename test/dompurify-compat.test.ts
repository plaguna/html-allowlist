import { describe, expect, test } from "vitest";
import { sanitize } from "../src/index";

// DOMPurify >=3.4.6 identifies nodes exclusively through getters cached from
// Node.prototype (anti-clobbering hardening). happy-dom's base
// Node.prototype.nodeName getter returns "" and each subclass shadows it, so
// every element read as nodeName "" and was treated as disallowed: allowed
// content was stripped wholesale and DOMPurify's child hoisting crashed at
// document level ("Only one element on document allowed"). The sanitizer now
// patches the base getter to be spec-compliant before invoking DOMPurify.
describe("dompurify cached-getter compatibility", () => {
  test("allowed content survives sanitization", () => {
    const out = sanitize("<p>keep</p><b>me</b><script>alert(1)</script>", [
      "p",
      "b"
    ]);
    expect(out).toContain("<p>keep</p>");
    expect(out).toContain("<b>me</b>");
    expect(out).not.toContain("<script");
  });

  test("Node.prototype.nodeName getter resolves names for every node type", () => {
    sanitize("<p>x</p>", ["p"]); // applies the compat patch to the active window
    const win = globalThis.window as unknown as {
      Node: { prototype: object };
    };
    const desc = Object.getOwnPropertyDescriptor(win.Node.prototype, "nodeName");
    expect(desc?.get).toBeDefined();
    const el = document.createElement("div");
    expect(desc!.get!.call(el)).toBe("DIV");
    const text = document.createTextNode("t");
    expect(desc!.get!.call(text)).toBe("#text");
    const comment = document.createComment("c");
    expect(desc!.get!.call(comment)).toBe("#comment");
  });
});
