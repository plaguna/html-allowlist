import type { WindowLike } from "dompurify";
import type { Window } from "happy-dom";
import { createRequire } from "node:module";
import { createSanitizerFromEnvironment } from "./core.js";

export { ConvergenceError, RuleSyntaxError, compileRules, createSanitizer } from "./core.js";
export type { CompiledPolicy, SanitizerConfig, Sanitizer, SanitizerWindow } from "./core.js";

let fallbackWindow: Window | null = null;

function configureHappyDomSettings(
  settings?: Partial<{
    disableJavaScriptEvaluation: boolean;
    disableJavaScriptFileLoading: boolean;
    disableCSSFileLoading: boolean;
    disableIframePageLoading: boolean;
    handleDisabledFileLoadingAsSuccess: boolean;
  }>
): void {
  if (!settings) return;
  settings.disableJavaScriptEvaluation = true;
  settings.disableJavaScriptFileLoading = true;
  settings.disableCSSFileLoading = true;
  settings.disableIframePageLoading = true;
  settings.handleDisabledFileLoadingAsSuccess = true;
}

const globalHappyDOM = (globalThis as { happyDOM?: { settings?: Record<string, boolean> } }).happyDOM;
configureHappyDomSettings(globalHappyDOM?.settings);

function loadHappyDom(): typeof import("happy-dom") {
  const require = createRequire(import.meta.url);
  try {
    return require("happy-dom") as typeof import("happy-dom");
  } catch (error) {
    throw new Error(
      "html-allowlist needs a DOM implementation in this environment. " +
        "Install happy-dom (`npm install happy-dom`), or run in an environment " +
        "that provides globalThis.DOMParser and globalThis.window.",
      { cause: error }
    );
  }
}

function getFallbackWindow(): Window {
  if (!fallbackWindow) {
    const { Window } = loadHappyDom();
    fallbackWindow = new Window();
    configureHappyDomSettings(fallbackWindow.happyDOM?.settings);
  }
  return fallbackWindow;
}

const sanitizer = createSanitizerFromEnvironment({
  onPassStart() {
    const happyDOM = (globalThis as { happyDOM?: { settings?: Record<string, boolean> } }).happyDOM;
    configureHappyDomSettings(happyDOM?.settings);
  },
  getDomParser() {
    if (globalThis.DOMParser) {
      return new globalThis.DOMParser();
    }
    return new (getFallbackWindow() as unknown as { DOMParser: new () => DOMParser }).DOMParser();
  },
  getDomWindow() {
    const win = globalThis.window;
    if (win && typeof win.DOMParser === "function") {
      return win as unknown as WindowLike;
    }
    return getFallbackWindow() as unknown as WindowLike;
  }
});

export const sanitize = sanitizer.sanitize;
export const sanitizeWithPolicy = sanitizer.sanitizeWithPolicy;
