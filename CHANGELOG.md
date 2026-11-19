# Changelog

All notable changes to **DevGuard** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-11-19

### Added
- **Lexical Constant Folding & Virtual View Infrastructure (`SpanMap`, Stage 5.3a & 5.3b):**
  - Exported `LexicalRegion` classification (`code`, `string`, `template`, `comment`, `regex`) from `analyzeLexicalStructure` with strict region boundary lookup (`isRangeStrictlyInCodeRegion`).
  - Added single-pass interval edit engine (`applyTextEditsWithSpanMap`), multi-pass span composition (`composeSpanMaps`), binary-search coordinate mapping (`toOrigSpan`, `toOrigLineAndCol`), and structural invariant verifier (`verifySpanMapInvariants`).
  - Implemented deterministic multi-pass fixed-point folding (`buildVirtualView`) in strict pass order `FOLD-03` (no-interpolation backtick templates) → `FOLD-01` (adjacent `+` string literals with operator-precedence guards rejecting `* / % == != === !== && || ?? ?: ?.`) → `FOLD-02` (string array `.join()`) → `FOLD-04` (safe bracket-to-dot member access with `MAX_BACKSCAN = 256`).
  - Enforced hard DoS caps (`MAX_FOLD_DEPTH = 4`, `MAX_FOLD_OPERANDS = 64`, `MAX_FOLDED_LENGTH = 4096`, `MAX_FOLD_EDITS = 2000`) with priority budgeting (`FOLD-03` flood cap, downstream `FOLD-02`/`FOLD-04` slot reservation, head/tail strided fallback, and security-sensitive context prioritization), $O(\log N)$ binary-search region/literal lookup, and deduplicated SARIF `fold_limit_exceeded` (`level: 'note'`) notifications per file when truncated.
- **Additive `Pass-V` Evaluation (`src/devguardAnalyzer.ts`):**
  - Re-runs detectors on virtual code `V` strictly when `editsApplied > 0`, maps `[line, endLine]` ranges back to original source `O` via `SpanMap` (including `;`-separated statements collapsed onto single virtual lines), deduplicates against `Pass-O`, applies range-aware inline suppressions on original lines `O`, and tags virtual findings with `[via-fold]`.
  - Evaluates `DG004-DYN-01/02` in `virtual-only` mode whenever folds occurred so statically resolvable expressions (e.g. `require("node:p" + "ath")`) fold cleanly without false dynamic-import warnings, and checks 2-arg / multi-line folded `import()` & `require()` calls in `DG004`.
- **Non-Scoring Dynamic Import/Require Visibility (`DG004-DYN-01` & `DG004-DYN-02`, Stage 5.2):**
  - Added lexical detection for non-literal `import(expr)` (`DG004-DYN-01`) and `require(expr)` (`DG004-DYN-02`) with syntactic exclusions (member calls, method definitions, zero-arg calls, comments/strings/regexes) and conservative local `require` shadow guard (`dynScopeUncertain`).
  - Enforced non-scoring guarantee (`severity: 'warning'`, `properties.scoring: false`, `security-severity: 3.5`), capped PR inline review annotations at `MAX_DYN_FINDINGS_PER_FILE = 20` (`+N more`), and implemented linear-time glob matching (`matchLinearGlob`) for base-branch `.devguard.json` allowlists.
- **Anti-Evasion Detectors & Shared Constants (Stage 5.4):**
  - Added **`DG008-EV-01`** for unbounded async `do { ... } while (true | 1)` loops (`warning`, `-10` correctness), sharing the single `isUnboundedAsyncLoopBody` helper with `DG008` and rejecting `.do()` member calls or standalone `{ ... } while (true) { ... }` blocks.
  - Extracted single canonical `CRITICAL_FLOW_IDENTIFIERS` (17 identifiers) and `matchesCriticalFlow` helper shared across `DG005` `try/catch` and **`DG005-EV-01`**.
  - Added **`DG005-EV-01`** for empty Promise `.catch(() => {})` / `_ => {}` / `function () {}` handlers (`warning`, `-10` maintainability) on critical receiver chains, with backward backbone parsing that ignores identifiers inside call arguments and restricts cleanup exemptions (`unlink`, `rmSync`, `close`, `JSON.parse`) to the call immediately preceding `.catch`.
- **Release Tooling & Validation (Stage 5.5):**
  - Added `--version` / `-v` CLI support in `src/cli.ts`, updated `scripts/corpus-report.ts` to cover `DG004-DYN-01/02`, and created `CHANGELOG.md`.
  - Validated `v1.3.0` offline across **10 external OSS repositories** (`4,318` analyzed files, `0` crashes/analysis failures), expanded the curated benchmark corpus to **129 cases** (`48 TP`, `63 TN` with `0` corpus FP, `18 EVASION`, `6` newly solved evasions), and verified **81/81 integration & corpus tests** (`Tests 1–80` + `Corpus Benchmark`).

### Changed
- **Hardened CLI Classification, Exclusions, & CI Invariants (Stage 5.1-hardening):**
  - Added automatic discovery for `.mjs`, `.cjs`, `.mts`, and `.cts` alongside explicit `partial` coverage telemetry for `.py` files and `ignored/excluded_path` accounting in `modified` diffs.
  - Changed `overall_score` when `analyzed === 0` from `100` to literal `N/A`, added 6-row strict PR status badge precedence, enforced fail-closed handling on `parse_error`/`internal_error`/invariant mismatches and invalid `DEVGUARD_FAIL_ON_UNANALYZABLE` values, and resolved `getDevGuardVersion()` dynamically up to 4 parent directories.
  - Anchored DevGuard self-reference exclusions strictly to root package repo paths and switched `npm test` script to deterministic in-process execution (`node .test-dist/tests/corpus.test.js && node .test-dist/tests/integration.test.js`) for Linux Node 22 CI reliability.

### Fixed
- Eliminated `DG001` false positives on benign `RegExp.prototype.exec()`, DOM helper member calls such as Playwright/jQuery `page.$eval()`, and JS/TS method declarations (`async exec() {}`) without weakening `.eval(...)` or standalone `eval(...)`/`exec(...)` sink detection.
- Hardened `DG008` and `DG008-EV-01` loop termination inspection (`isUnboundedAsyncLoopBody`) with scope-aware brace stripping so inner `for`/`switch` `break` statements and nested callback/function `return` statements cannot evade unbounded async loop detection (while honoring labeled outer breaks).
- Fixed `DG004` (`detectHallucinatedPackages`) to cover 2-argument `import('pkg', { with: ... })` and multi-line folded `import(...)` / `require(...)` specifiers.
- Restored `"allowImportingTsExtensions": false` in `tsconfig.test.json` (using `rewriteRelativeImportExtensions` cleanly with `tsc`) and blocked `?.` property-access chains immediately trailing `FOLD-01` literals (`"a" + "b"?.length`) from unsafe folding.

## [1.2.1] - 2026-11-16

### Added
- Zero-dependency test harness (`corpus.test.ts` + `integration.test.ts`, Tests 1–34) with `n = 61` labeled corpus baseline (`docs/benchmarks/realworld-2026-11-16.md`).
- Hardened PR comment sanitization, base-branch `.devguard.json` verification, fork PR safety (`pull_request` + `upload-sarif` guard), and pre-LLM layout-preserving secret redaction with residual entropy gate.

## [1.2.0] - 2026-11-10

### Added
- Hybrid Dual-Layer Audit Architecture combining offline Layer 1 rules (`DG001`–`DG008`) with optional Layer 2 Gemini reasoning, sticky PR comments, one-click inline `suggestion` blocks, and OASIS SARIF v2.1.0 output.
