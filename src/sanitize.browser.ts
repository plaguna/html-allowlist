import type { WindowLike } from "dompurify";
import { createSanitizerFromEnvironment } from "./core.js";

export { ConvergenceError, RuleSyntaxError, compileRules, createSanitizer } from "./core.js";
export type { CompiledPolicy, SanitizerConfig, Sanitizer, SanitizerWindow } from "./core.js";

const sanitizer = createSanitizerFromEnvironment({
  getDomParser() {
    if (globalThis.DOMParser) {
      return new globalThis.DOMParser();
    }
    throw new Error("DOMParser is not available in this environment.");
  },
  getDomWindow() {
    const win = globalThis.window as unknown as WindowLike | undefined;
    if (win && typeof (win as { document?: Document }).document !== "undefined") {
      return win;
    }
    throw new Error("window is not available in this environment.");
  }
});

export const sanitize = sanitizer.sanitize;
export const sanitizeWithPolicy = sanitizer.sanitizeWithPolicy;
