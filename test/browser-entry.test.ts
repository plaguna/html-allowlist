import { describe, expect, test } from "vitest";
import { sanitize } from "../src/index.browser.js";

describe("browser entrypoint", () => {
  test("requires DOMParser and does not fall back to happy-dom", () => {
    const original = globalThis.DOMParser;
    (globalThis as { DOMParser?: typeof DOMParser }).DOMParser = undefined;
    try {
      expect(() => sanitize("<p>ok</p>", ["p"])).toThrow(/DOMParser/i);
    } finally {
      (globalThis as { DOMParser?: typeof DOMParser }).DOMParser = original;
    }
  });

  test("requires a window with a document", () => {
    const originalWindow = (globalThis as { window?: Window }).window;
    (globalThis as { window?: Window }).window = undefined as unknown as Window;
    try {
      expect(() => sanitize("<p>ok</p>", ["p"])).toThrow(/window/i);
    } finally {
      (globalThis as { window?: Window }).window = originalWindow;
    }
  });
});
