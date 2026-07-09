// Coverage-guided fuzz target for compileRules() (Jazzer.js / libFuzzer).
//
// compileRules is the public entry point that handles fully untrusted rule
// strings; its contract is to reject malformed rules with RuleSyntaxError
// and nothing else. Any other exception escaping it is a robustness bug and
// is reported by Jazzer.js as a finding.
//
// Run: npm run fuzz:rules

import { FuzzedDataProvider } from "@jazzer.js/core";
import { RuleSyntaxError, compileRules } from "../dist/index.js";

export function fuzz(data) {
  const fdp = new FuzzedDataProvider(data);
  const config = {
    allowCommonAttributes: fdp.consumeBoolean(),
    allowDataImageUrls: fdp.consumeBoolean(),
    dangerouslyAllowJavaScript: fdp.consumeBoolean()
  };
  const rules = fdp.consumeStringArray(16, 64);

  try {
    compileRules(rules, config);
  } catch (error) {
    if (!(error instanceof RuleSyntaxError)) {
      throw error;
    }
  }
}
