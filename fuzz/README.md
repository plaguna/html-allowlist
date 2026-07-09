# Fuzzing

Coverage-guided fuzzing for html-allowlist, powered by [Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js) (libFuzzer for Node.js). This complements the fast-check property tests in `test/`: the properties run on every `npm test` with a fixed seed, while these targets run open-ended, mutation-based exploration with coverage feedback.

## Targets

| Target | What it checks |
| --- | --- |
| `sanitize.fuzz.js` | Full pipeline. Each input picks one of two rule-generation modes, then a config (from fixed pools, so every exec reaches the HTML path) and an HTML document (the mutated remainder): **pooled** draws rules from small fixed pools, independent of the HTML, and is best at exercising rejection/stripping paths since most mutated content matches no rule; **derived** reverse-engineers a rule list from the HTML itself (every tag/attr/style property it contains is allowed), so the mutator's own structure is retained and pushed through the transform paths instead of dropped, including tags/attrs the pooled mode's fixed lists never cover. Acts as an **invariant oracle**: with `dangerouslyAllowJavaScript: false` it throws a finding if a `<script>`, `on*` attribute, `javascript:` URL, or unsafe `data:` URL survives, or if output is not a fixed point (`sanitize(output) !== output`) — including when the derived rules explicitly allow the tag/attribute in question. Any exception other than `ConvergenceError` is also a finding. |
| `compile-rules.fuzz.js` | Rule parser robustness: `compileRules` must reject malformed rules with `RuleSyntaxError` and never leak any other exception. |

Known blind spot: the sanitize oracle re-parses output with the same happy-dom parser the sanitizer uses, so happy-dom↔browser parser differentials (mXSS) are out of scope here; those are covered by the DOMPurify layer and `test/xss-vectors.test.ts`.

## Running locally

```bash
npm run fuzz          # sanitize target, runs until Ctrl-C
npm run fuzz:rules    # compileRules target, runs until Ctrl-C
npm run fuzz:smoke    # both targets, time-boxed (~90s total)
```

Extra libFuzzer flags go after `--`, e.g. `npm run fuzz -- -- -max_total_time=600`.

> **Do not add `--sync` to the sanitize target**, even though Jazzer suggests it.
> happy-dom retains DOM nodes through `WeakRef`/`FinalizationRegistry`, and V8 keeps
> WeakRef targets alive until the end of the current *job*. In synchronous mode the
> fuzzer never returns to the event loop, so every parsed `Document` stays reachable
> and RSS climbs until libFuzzer reports a spurious out-of-memory (observed at ~16k
> runs). In async mode RSS plateaus around 1 GB indefinitely. This is not a leak in
> the library: a plain synchronous `for` loop around `sanitize()` reproduces the
> growth, and yielding to the event loop every N calls makes it flat. `compile-rules`
> touches no DOM, so it keeps `--sync` and runs ~20x faster.

- `fuzz/corpus/<target>/` — committed seed corpus (curated XSS vectors and rule strings). Seeds are `N` prefix bytes (consumed for rule/config choices) followed by the HTML payload.
- `fuzz/generated/<target>/` — corpus growth from local runs; gitignored. libFuzzer writes newly-interesting inputs to the first corpus directory and reads seeds from the second.
- `fuzz/sanitize.dict` — libFuzzer dictionary of HTML/CSS/URL tokens.
- `fuzz/generate-corpus.js` — generates `fuzz/corpus/sanitize/generated-*` seeds by hand-encoding the exact `FuzzedDataProvider` byte stream a scenario needs, rather than hoping the mutator stumbles onto a rule+HTML pairing that exercises it: multiset tag counts, each style-selector shape, specific tag+attribute combinations, and known-tricky documents (prototype-colliding tag names, ambiguous `srcset` commas). Re-run with `node fuzz/generate-corpus.js` after changing `TAG_POOL`/`ATTR_RULE_POOL`/`STYLE_RULE_POOL` in `sanitize.fuzz.js`, which it imports from directly so the two can't drift.
- Crash reproducers (`crash-*`, `timeout-*`, `oom-*`) land in the repo root and are gitignored. Reproduce with `npx jazzer fuzz/sanitize.fuzz.js crash-<hash> --sync -- -runs=1`.

## Findings so far

**Fixed in this library.** `isDangerousUrl` checked `javascript:` and `data:` but not `vbscript:`, relying on DOMPurify's default scheme regex to reject it incidentally. That held for a single-candidate `srcset` value, but a malformed multi-candidate one let a `vbscript:` entry through DOMPurify's own `srcset` validation while an otherwise-identical `javascript:` entry in the same shape was still caught. `vbscript:` is IE-only and long dead, but the check is free and now runs in our own pre-filter. Found via a hand-crafted seed from `fuzz/generate-corpus.js` (`generated-srcset-mixed-safety`) after libFuzzer mutated it into the malformed shape. Regression tests in `test/sanitize.test.ts`.

**Fixed in this library.** `filterAttributes` looked up `allowCommonAttributes` defaults with a plain object keyed by tag name (`COMMON_ATTRS[tag]`). For a tag matching an inherited `Object.prototype` property — `constructor`, `toString`, `valueOf`, `hasOwnProperty`, and others — the lookup returned that inherited value (e.g. the `Object` constructor function) instead of `undefined`, and `for (const attr of common)` then threw because it isn't iterable. Reachable as a denial-of-service on any caller with `allowCommonAttributes: true` and a policy allowing such a tag, triggered purely by attacker-controlled HTML (e.g. `<constructor>`). `COMMON_ATTRS` is now a `Map`. Found by the **derived** rule mode within its first ~150K execs (~1 minute) — the pooled mode's fixed 19-tag pool can never produce a tag named `constructor`, since it only ever generates rules from that list. Regression tests in `test/sanitize.test.ts`.

**Fixed in this library.** `collectElements` read `.content` on every element to descend into `<template>` content. That property is meaningful only on `<template>`: a `<form>` exposes its controls as named properties, so `form.content` performs a named-item lookup, and happy-dom implements that by interpolating the form's `id` into a CSS selector without escaping it. An `id` of `"` produced `input[form="""]` and threw a `DOMException` out of `sanitize()` — reachable with an *empty rule list*, so no policy could prevent it. It was also a DOM-clobbering surface (a control named `content` shadows the property). Now gated on `tagName`, which cannot be clobbered. Regression tests in `test/sanitize.test.ts`.

**Known upstream (happy-dom), pinned with `test.fails`** so they surface the moment they're fixed, and matched narrowly in `isExpectedError` so the fuzzer keeps hunting for new defects:

1. `HTMLFormElement` builds `input[form="${id}"]` without escaping, so any property read on a form with a quote-bearing `id` throws. DOMPurify's walk reads `.content` on every node, so it trips whenever such a form survives the policy. Repro: `sanitize('<form id=&quot;></form>', ['form','form|id'])`.
2. `HTMLSerializer` reads `.content` on any element named `template`, but an SVG-namespaced `<template>` is not an `HTMLTemplateElement` and has none, so serialization throws. Reproducible with no html-allowlist at all: `document.body.innerHTML = '<svg><template>x</template></svg>'; document.documentElement.outerHTML`. Repro: `sanitize('<svg><template>x</template></svg>', ['template'])`.

Neither matches an existing happy-dom issue; both are worth reporting upstream.

## CI

`.github/workflows/fuzz.yml` runs both targets weekly (and on manual dispatch, with a configurable time budget for the sanitize target) and uploads reproducer files as artifacts on failure. Fuzzing is deliberately kept off the push/PR path.

## OSS-Fuzz

`fuzz/oss-fuzz/` stages the three files an [OSS-Fuzz](https://github.com/google/oss-fuzz) integration needs (`project.yaml`, `Dockerfile`, `build.sh`). They do not run from this repository — OSS-Fuzz integration works by submitting them upstream:

1. Fork `google/oss-fuzz`, copy `fuzz/oss-fuzz/*` to `projects/html-allowlist/`.
2. Test locally (needs Docker):
   ```bash
   cd oss-fuzz
   python infra/helper.py build_image html-allowlist
   python infra/helper.py build_fuzzers html-allowlist
   python infra/helper.py check_build html-allowlist
   python infra/helper.py run_fuzzer html-allowlist fuzz_sanitize
   ```
3. Open a PR against `google/oss-fuzz`.

Notes:

- **Acceptance is not automatic.** OSS-Fuzz [prioritizes projects with a significant user base or criticality to infrastructure](https://google.github.io/oss-fuzz/faq/#how-do-you-decide-which-projects-to-accept). A security-sensitive HTML sanitizer is squarely in their wheelhouse, but a young library may be asked to demonstrate adoption first.
- `primary_contact` in `project.yaml` must be a Google-account email; it receives bug reports and gains access to the ClusterFuzz dashboards.
- ClusterFuzzLite (OSS-Fuzz's run-it-in-your-own-CI sibling) does **not** support JavaScript, which is why CI fuzzing here uses Jazzer.js directly in a plain GitHub Actions job instead.
- `build.sh` copies the targets to dot-free names (`fuzz_sanitize`, `fuzz_compile_rules`) because OSS-Fuzz target names must match `[a-zA-Z0-9_-]+` and the name is derived from the filename.
