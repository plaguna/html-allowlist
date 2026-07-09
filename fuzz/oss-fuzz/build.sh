#!/bin/bash -eu
# OSS-Fuzz build script for html-allowlist.
# Lives at projects/html-allowlist/build.sh in google/oss-fuzz once accepted.

cd "$SRC/html-allowlist"

npm install
npm run build

# OSS-Fuzz derives the target name via `basename -s .js` and requires it to
# match [a-zA-Z0-9_-]+ (no dots), so stage dot-free copies of the *.fuzz.js
# targets before compiling. This must happen before the first
# compile_javascript_fuzzer call, which snapshots the project into $OUT.
cp fuzz/sanitize.fuzz.js fuzz/fuzz_sanitize.js
cp fuzz/compile-rules.fuzz.js fuzz/fuzz_compile_rules.js

# compile_javascript_fuzzer <project dir in $SRC> <fuzz target path> [jazzer flags]
# fuzz_sanitize must NOT use --sync: happy-dom retains DOM nodes via WeakRef,
# and V8 only collects those once the job ends, so synchronous fuzzing grows
# RSS until ClusterFuzz reports a spurious OOM. See fuzz/sanitize.fuzz.js.
compile_javascript_fuzzer html-allowlist fuzz/fuzz_sanitize.js
# compileRules touches no DOM, so --sync is safe and ~20x faster there.
compile_javascript_fuzzer html-allowlist fuzz/fuzz_compile_rules.js --sync

# libFuzzer picks up $OUT/<target>.dict automatically and ClusterFuzz unpacks
# $OUT/<target>_seed_corpus.zip.
cp fuzz/sanitize.dict "$OUT/fuzz_sanitize.dict"
zip -j "$OUT/fuzz_sanitize_seed_corpus.zip" fuzz/corpus/sanitize/*
zip -j "$OUT/fuzz_compile_rules_seed_corpus.zip" fuzz/corpus/compile-rules/*
