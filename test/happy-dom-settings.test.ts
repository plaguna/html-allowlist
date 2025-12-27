import { describe, expect, test } from "vitest";

describe("happy-dom settings", () => {
  test("disables external resource loading globally", () => {
    const settings = (globalThis as { happyDOM?: { settings?: Record<string, boolean> } }).happyDOM?.settings;
    expect(settings).toBeDefined();
    if (!settings) return;
    expect(settings.disableJavaScriptEvaluation).toBe(true);
    expect(settings.disableJavaScriptFileLoading).toBe(true);
    expect(settings.disableCSSFileLoading).toBe(true);
    expect(settings.disableIframePageLoading).toBe(true);
    expect(settings.handleDisabledFileLoadingAsSuccess).toBe(true);
  });
});
