# 🛡️ DevGuard v1.7.0 — The AI-Slop & Vibe-Coding Security Gatekeeper

[![Zero-Dependency Runtime](https://img.shields.io/badge/Runtime-100%25%20Zero--Dependency-emerald.svg)](#hybrid-dual-layer-architecture)
[![OASIS SARIF v2.1.0](https://img.shields.io/badge/SARIF-v2.1.0%20Compliant-blue.svg)](#quick-start-choose-your-path)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-v1.7.0-black.svg)](#quick-start-choose-your-path)
[![Tests 95/95 Passing](https://img.shields.io/badge/Tests-95%2F95%20Passing-success.svg)](#local-development--verification)

**DevGuard** is a deterministic CI/CD security gatekeeper engineered to catch silent failures, slopsquatting, leaked API keys, and financial race conditions hidden inside AI-generated (*Cursor, Windsurf, Copilot, Antigravity*) Pull Requests before they reach production.

Unlike generic LLM code reviewers that only leave probabilistic chat comments, DevGuard combines an **offline, low-latency Deterministic Lexical & Heuristic Engine** (`Pass-O` + additive `Pass-V` virtual constant folding) with optional **Gemini Adversarial Reasoning**, posts **One-Click GitHub Suggested Changes** directly on offending diff lines, and uploads **OASIS SARIF v2.1.0** reports to GitHub Code Scanning.

---

## ⚡ Quick Start: Choose Your Path

DevGuard supports four workflows depending on whether you are exploring in the browser, auditing locally in your terminal, connecting AI coding agents via MCP, or gating Pull Requests in CI:

| Path | Best For | Monorepo `DG004` Resolver & Base-Branch `.devguard.json`? |
| :--- | :--- | :---: |
| **Path A: Local Browser Dashboard** | Testing a single code snippet interactively in the browser | No *(single-file mode)* |
| **Path B: Zero-Dep CLI & Pre-Commit Hook** | Running fast pre-commit audits locally in terminal via `npx devguard` | **Yes** *(reads working tree & git index)* |
| **Path C: GitHub Actions CI (Recommended)** | Protecting repositories, Pull Requests, & monorepos with SARIF + inline fixes | **Yes** *(requires `fetch-depth: 0`)* |
| **Path D: Zero-Dep MCP Server (`devguard mcp`)** | Giving AI IDEs/agents read-only offline security audits over stdio JSON-RPC 2.0 | **Yes** *(for `devguard_check_files`; snippet mode is single-file)* |

### Path A: Try Quickly in the Browser Dashboard (Single-File Snippets)

```bash
npm install
npm run dev
```

Open the local dashboard URL printed in your terminal and paste any JS/TS/Python snippet to inspect deterministic Layer 1 findings immediately.
> [!NOTE]
> The browser dashboard audits standalone snippets without repository git history. Importing internal monorepo workspace packages (e.g., `@myorg/ui`) in the browser will trigger `DG004`; use **Path B (CLI)** or **Path C (GitHub Actions CI)** for full monorepo workspace resolution.

### Path B: Zero-Dependency CLI & Pre-Commit Hook (`npx devguard`)

Run DevGuard directly from your terminal or install a Git pre-commit hook with zero setup:

```bash
# Audit staged files before committing
npx devguard check --staged

# Audit specific files or directories
npx devguard check src/

# Install idempotent Git pre-commit hook
npx devguard install-hook
```

### Path C: Install in GitHub Actions CI (Fork-Safe & Monorepo-Ready)

Pin DevGuard by release tag or **full 40-character commit SHA** (`git rev-parse v1.6.0^{commit}`) in `.github/workflows/devguard.yml`. Always set **`fetch-depth: 0`** on `actions/checkout@v4` so DevGuard can read `origin/<baseRef>` for base-branch `.devguard.json` and monorepo workspace configs (avoiding shallow-clone `DG004-WS-SHALLOW` fallbacks):

```yaml
name: DevGuard Security Audit

on:
  pull_request:
    branches: [ main, master ]
  push:
    branches: [ main ]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  audit:
    name: DevGuard Quality Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Required so base-branch .devguard.json & workspace configs are readable

      - name: Run DevGuard v1.7.0
        id: devguard
        uses: OkyWoww/DevGuard@v1.7.0 # Or pin by 40-char commit SHA (git rev-parse v1.7.0^{commit})
        with:
          # Optional: Omit for 100% Free Offline Single-Pass Lexical & Heuristic mode
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
          min_score: '85'
          target_files: 'modified'
          fail_on_unanalyzable: 'false'

      - name: Upload DevGuard SARIF Report to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always() && (github.event_name != 'pull_request' || (github.event.pull_request.head.repo != null && github.event.pull_request.head.repo.full_name == github.repository))
        with:
          sarif_file: ${{ steps.devguard.outputs.sarif_file }}
```

### Path D: Zero-Dependency MCP Server (`devguard mcp`)

Expose DevGuard's deterministic offline engine directly to MCP-compatible AI coding clients (Antigravity, Cursor, Claude Desktop, VS Code, or `@modelcontextprotocol/inspector`) over newline-delimited **stdio JSON-RPC 2.0** with **zero third-party MCP SDK dependencies** (`"dependencies": {}`):

```json
{
  "mcpServers": {
    "devguard": {
      "command": "node",
      "args": ["/path/to/devguard/dist/cli.js", "mcp", "--workspace", "/path/to/your/repo"]
    }
  }
}
```

* **Supported MCP Protocol Versions:** `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05` (strictly negotiated in `initialize`; unknown versions rejected with `-32602`).
* **3 Read-Only Offline Tools** (all annotated `readOnlyHint: true`, `destructiveHint: false`, `openWorldHint: false`):
  * `devguard_check_files` (`paths`, optional `min_score`) — audits workspace-relative files with exact CLI JSON score/finding parity (`Test 93` / `A8-1`).
  * `devguard_check_snippet` (`language`, `code`, optional `virtual_path`, `min_score`) — audits in-memory snippets without touching disk.
  * `devguard_explain_rule` (`rule_id`) — explains `DG001`–`DG008` and `DG004-DYN`/`DG004-WS` rules with CWE, remediation, and TP/TN examples.
* **Security Hardening (`SPEC §8.3`):** Strict path jail rooted at `--workspace` (blocks `..`, absolute/UNC/drive-relative paths, prefix collisions, and symlink escapes), prompt-injection isolation (`quoted_source` separated from `message`/`suggestion` with `security_boundary`), automatic secret redaction (`INV-3`), pure JSON-RPC 2.0 `stdout` framing (diagnostics to `stderr`), and hard resource bounds (`1 MiB` incoming line, `25` files/call, `256 KiB` snippet, `512 KiB` bounded JSON output). Verified via official `@modelcontextprotocol/inspector@0.16.8` (`A8-5`).

### Action Inputs & Outputs ([action.yml](action.yml))

| Direction | Name | Default / Example | Description |
| :--- | :--- | :--- | :--- |
| **Input** | `gemini_api_key` | `""` | Optional Google Gemini API key for Layer 2 reasoning (falls back cleanly to Offline Lexical & Heuristic mode if omitted, forked, or rate-limited). |
| **Input** | `min_score` | `'85'` | Minimum Overall Guard score (`0`–`100`) required to pass CI (`DEVGUARD_MIN_SCORE`). |
| **Input** | `target_files` | `'modified'` | Audit scope: `'modified'` (git diff), `'all'` (workspace scan), or a specific file path (`DEVGUARD_TARGET`). |
| **Input** | `fail_on_unanalyzable` | `'false'` | Strict `'true'` or `'false'` (`DEVGUARD_FAIL_ON_UNANALYZABLE`); when `'true'`, fail (`exit 1`) if any in-scope code file is skipped (`unsupported_language` / `file_too_large`). Invalid values exit `1`. |
| **Output** | `overall_score` | `96` / `N/A` | Aggregate Overall Guard score across analyzed files (`0`–`100`), or string `N/A` when `0` files were analyzed (numeric consumers must guard against `N/A`). |
| **Output** | `audit_status` | `PASS` / `FAIL` | Final gate verdict written to `GITHUB_OUTPUT`. |
| **Output** | `sarif_file` | `devguard-results.sarif` | Path to generated OASIS SARIF v2.1.0 report (`%SRCROOT%` POSIX URIs, GitHub Code Scanning `security-severity` rating `3.5`–`9.5`, and `fold_limit_exceeded` notifications). |

### Quick Reference: Blocking Findings vs. Non-Scoring Notices

Not every message in a DevGuard PR comment fails your build. Use this quick glossary to tell **scoring/blocking findings** apart from **informational fail-closed notices**:

| Code / Category | Fails CI Gate? | What It Means & What To Do |
| :--- | :---: | :--- |
| **`DG001`, `DG003`, `DG004`, `DG005` (`error`), `DG006`, `DG007`, `DG008`** | **Yes** *(scoring)* | Security or correctness defect that deducts from the Overall Guard score and fails the gate below `min_score`. Fix the flagged line (or use the inline GitHub suggestion). |
| **`DG004-WS-SHALLOW`** | **No** *(non-scoring)* | CI ran with a shallow clone (`fetch-depth: 1`) so `origin/<baseRef>` could not be read; workspace resolution failed closed to `0` base packages. Add `fetch-depth: 0` to `actions/checkout@v4`. |
| **`DG004-WS-NEW`** | **No** *(non-scoring)* | The PR introduces a new workspace package not yet on the base branch. For anti-bypass security, it is not auto-trusted until merged into the base branch. |
| **`DG004-WS-UNPARSED`** | **No** *(non-scoring)* | A workspace config (`package.json`, `pnpm-workspace.yaml`, or `tsconfig.json`) exceeded `256 KiB` or used unsupported YAML/JSONC constructs; that source failed closed safely without blocking by itself. |
| **`DG004-DYN-01` / `DG004-DYN-02`** | **No** *(non-scoring)* | Non-literal dynamic `import(...)` / `require(...)` specifier surfaced for supply-chain visibility (`scoring: false`). |
| **`DG001-ALIAS-01`** | **No** *(non-scoring)* | Intra-procedural alias (max depth 2) to dynamic execution sinks (`eval`, `Function`, `child_process.exec`) surfaced for visibility (`scoring: false`). |
| **`DG005-ALIAS-01`** | **No** *(non-scoring)* | Intra-procedural alias (max depth 2) to a critical-flow Promise that swallows rejection via an empty `.catch()` callback (`scoring: false`). |

---

## 🎯 Why DevGuard?

Modern AI coding assistants accelerate delivery, but frequently introduce subtle, high-impact defects ("AI-Slop") that pass traditional linters and unit tests:

* **Slopsquatting, Phantom Imports, & Dynamic Loaders:** Hallucinated or typosquatted NPM packages (`lodahs`, `express-jwt-verify`), subpaths absent from `package.json`, or unanalyzable dynamic `import()` / `require()` specifiers (`DG004-DYN-01/02`).
* **Lexically Obfuscated Payloads:** Split secret strings (`"sk_live_" + "..."`), `['a','b'].join('')`, or computed member lookups (`globalThis["ev" + "al"]`, `wallet["bal" + "ance"]`, `pay["char" + "ge"]`) unfolded safely via deterministic `Pass-V` constant folding (`[via-fold]`).
* **Silent Failure Slop:** Empty `catch (e) {}` blocks, `console.*`-only handlers, and empty Promise `.catch(() => {})` handlers (`DG005-EV-01`) swallowing critical payment, authentication, or database failures.
* **Check-Then-Act Financial Race Conditions (TOCTOU):** Non-atomic balance, credit, or stock mutations separated by `await` calls without transactions or locks, enabling double-spending under concurrent load.
* **Hardcoded AI & Payment Keys:** Prototype API keys (`AIzaSy...`, `sk_live_...`, `ghp_...`, credentialed DB URIs, PEM keys, JWTs) accidentally committed into Pull Requests.
* **Unbounded Async Loops & Hanging Fetches:** `while (true)` / `for (;;)` and `do { ... } while (true | 1)` (`DG008-EV-01`) async polling loops without exit bounds or `fetch()` calls missing `AbortSignal.timeout()`, leading to worker exhaustion and runaway API bills.

---

## 📋 Deterministic Gatekeeper Rules (`DG001`–`DG008`, `DG004-DYN-01/02`)

Layer 1 runs **100% offline with zero third-party runtime dependencies** (`package.json` `"dependencies": {}`). Operating as a **Deterministic Lexical & Heuristic Engine** (`analyzeLexicalStructure` + `buildVirtualView` + rule heuristics), it is immune to LLM prompt-injection comments inside source code, with verified lexical evasion boundaries documented in the [Benchmark Corpus section](#benchmark-corpus-known-limitations--behavior-changes).

| Rule ID | Category | Detection Target | SARIF Severity Rating | Default Severity | Inline Auto-Fix Suggestion |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **`DG001`** | Code Execution & Traversal | Arbitrary `eval()`, `new Function()`, unsanitized shell execution (`exec`), XSS sinks, and uncontained path traversal | `9.5` | `error` | Yes |
| **`DG002`** | Quality & Defense-in-Depth | Defense-in-depth hardening guidance explaining secondary deductions under zero-leniency audit | `5.0` | `warning` | — |
| **`DG003`** | Adversarial Audit / Gate Failure | Deep semantic or threshold gate failure when no standalone `DG001`/`inlineFindings` error was emitted | `8.0` | `error` | Yes |
| **`DG004`** | Supply Chain / Slopsquatting | Typosquatted NPM imports (Damerau-Levenshtein distance) & phantom dependencies / `#subpath` imports missing from `package.json` | `7.5` | `error` | Yes |
| **`DG004-DYN-01`** | Supply Chain Visibility | Unanalyzable non-literal dynamic `import(...)` specifiers (evaluated in `virtual-only` mode when folds occur; **non-scoring**) | `3.5` | `warning` (`scoring: false`) | — |
| **`DG004-DYN-02`** | Supply Chain Visibility | Unanalyzable non-literal `require(...)` specifiers with `require` shadow guard (`virtual-only` mode when folds occur; **non-scoring**) | `3.5` | `warning` (`scoring: false`) | — |
| **`DG005`** | Silent Failure Slop | Swallowed `try/catch` exceptions (`error` in critical flows, `warning` elsewhere) and empty `.catch(() => {})` on critical receiver chains (`DG005-EV-01`, `warning`) | `7.0` | `error` / `warning` | Yes |
| **`DG006`** | Financial Concurrency | Non-atomic balance/stock mutations (`check-then-act` TOCTOU across `await` boundaries without transactions/locks) | `8.5` | `error` | Yes (`db.$transaction`) |
| **`DG007`** | Credential & Secret Leak | Hardcoded provider keys, PEM private keys, credentialed URIs, JWTs & high-entropy secret literals | `9.0` | `error` | Yes (`process.env`) |
| **`DG008`** | Infrastructure Resilience | Unbounded async `while (true)` / `for (;;)` loops (`error`), `do { ... } while (true \| 1)` (`DG008-EV-01`, `warning`), & external `fetch()` calls missing `AbortSignal.timeout()` / `AbortController` | `6.5` | `error` / `warning` | Yes (`AbortSignal.timeout` / bounded loop) |

---

## 🧩 v1.3.0 Lexical Constant Folding (`Pass-V`), `SpanMap`, & Additive Evasion Architecture

In `v1.3.0`, DevGuard introduces a deterministic, syntax-guarded **Virtual Folding Engine** ([src/rules/spanMap.ts](src/rules/spanMap.ts)) running alongside baseline `Pass-O`:

1. **Four Conservative Constant-Folding Operations (`FOLD-03` → `FOLD-01` → `FOLD-02` → `FOLD-04`):**
   * **`FOLD-03` (Template Simplification):** Rewrites backtick templates without `${...}` interpolation, newlines, or escapes into single-quoted string literals (e.g., `` `foo` `` → `'foo'`).
   * **`FOLD-01` (String Concatenation):** Folds adjacent same-sign string literal `+` chains (e.g., `'sk_live_' + '51H9...'`) with strict binary operator precedence guards (rejecting `* / % == != === !== && || ?? ?: ?.`), avoiding false folds on `"a" + b + "c"` or `"1" + "2".length`.
   * **`FOLD-02` (Array Join Folding):** Folds pure string literal array `.join()` calls (e.g., `['sk', 'live', '51H9...'].join('_')`) with delimiter validation and multiline/escape exclusion.
   * **`FOLD-04` (Bracket-to-Dot Member Access):** Rewrites safe identifier bracket lookups (e.g., `globalThis["eval"]`, `wallet["balance"]`, `wallet["deduct"]`) to dot notation using backward scanning (`MAX_BACKSCAN = 256`) to reject declarations (`const x["a"]`), computed object properties (`{ ["a"]: 1 }`), destructuring, and keyword collisions.
2. **Additive `Pass-V` & `SpanMap` Remapping ([src/devguardAnalyzer.ts](src/devguardAnalyzer.ts)):**
   * When `editsApplied === 0`, DevGuard skips the secondary `Pass-V` detector pass (`+0.02%` measured overhead on the `108`-case non-fold baseline subset vs `Pass-O` alone) and produces identical results to `Pass-O`.
   * When `editsApplied > 0`, detectors re-run on virtual code `V`, map `[line, endLine]` spans back to original source `O` via binary-search `toOrigLineAndCol` / `toOrigSpan` (`SpanMap`) — including semicolon-separated statements collapsed onto a single virtual line — deduplicate against `Pass-O`, apply range-aware inline suppressions on original lines `O`, and tag virtual-only findings with `[via-fold]`.
   * `DG004-DYN-01/02` runs in `virtual-only` mode whenever `editsApplied > 0`, automatically silencing spurious dynamic-specifier warnings on statically resolvable concatenations such as `require("node:p" + "ath")`.
3. **Deterministic DoS Bounds, Priority Budgeting, & SARIF Visibility:**
   * Hard-capped at `MAX_FOLD_DEPTH = 4`, `MAX_FOLD_OPERANDS = 64`, `MAX_FOLDED_LENGTH = 4096`, `MAX_FOLD_EDITS = 2000`, and `MAX_BACKSCAN = 256` with $O(\log N)$ binary-search region/literal lookups and non-overlapping monotonic `SpanMap` invariants verified by property tests.
   * When a file exceeds `MAX_FOLD_EDITS`, priority scheduling caps noisy `FOLD-03` backtick floods, reserves edit capacity for downstream `FOLD-02`/`FOLD-04` transforms, prioritizes security-sensitive/dynamic-sink contexts (`eval`, `require`, `import`, secret prefixes, balance/transfer/fetch chains), and spreads fallback selection across head/tail regions before emitting a deduplicated SARIF `fold_limit_exceeded` (`level: "note"`) notification.

---

## 🧮 Scoring Formula, CI Gate Threshold, & Severity Escalation

### Category Scoring & Zero-Leniency Caps
1. **Per-Category Rubric (`0`–`100`):** Each file starts with `security = 100`, `correctness = 100`, and `maintainability = 100`. Every matching finding subtracts its category penalty clamped at zero (`Math.max(0, 100 - sum(penalties))`).
2. **Overall Score:** `totalScore = Math.round((security + correctness + maintainability) / 3)`.
3. **Zero-Leniency Hardening Flag:** `isHardened = !(security < 80 || correctness < 75 || criticalFindings.length > 0) && totalScore >= 88`. Files below strict zero-leniency criteria never pass silently as hardened, and Layer 2 Gemini scores are strictly capped (`Math.min(layer1Score, geminiScore)`) by Layer 1 findings.
4. **CI Gate Decision (`runAction`):** A file fails the CI gate (causing CLI exit code `1`) if **any** of the following hold:
   * `totalScore < minScore` (default `minScore = 85`, configurable via `DEVGUARD_MIN_SCORE` or Action input `min_score`)
   * `!isHardened && security < 70`
   * `inlineFindings` contains any item with `severity === 'error'`
   * Note: `DG004-DYN-01` and `DG004-DYN-02` carry `severity: 'warning'` and `scoring: false`, so they **never** subtract points or fail `min_score` (PR inline reviews cap DYN output at `MAX_DYN_FINDINGS_PER_FILE = 20` with `+N more`, while SARIF emits all unclipped results).
5. **Coverage Classification, Partial `.py`, & `N/A` Score Semantics:**
   * Every in-scope file (after pre-existing path exclusions) is classified once into:
     * **Analyzed (`full`):** Supported JS/TS extensions (`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.mts`, `.cts`) within the `1_048_576`-byte (`1 MiB`) limit.
     * **Analyzed (`partial`):** `.py` files within the `1_048_576`-byte limit run only the language-agnostic rules that operate on Python (`DG001` generic `eval`/`exec`/`os.system` sinks plus SQL/ping domain heuristics, `DG002` defense-in-depth / error-handling resilience notes, and `DG007` hardcoded secrets) while skipping JS/TS/NPM-specific detectors (`DG004`, `DG004-DYN-*`, `DG005`, `DG006`, and `DG008`), and are explicitly labeled `Partial: language-agnostic rules only`.
     * **Skipped:** Recognized non-analyzed code languages (`.pyw`, `.go`, `.java`, `.rb`, `.php`, `.rs`, `.vue`, `.svelte`, `.astro`, `.ipynb`, extensionless `#!` scripts), files exceeding `1_048_576` bytes (`file_too_large`, checked via `stat`), `parse_error`, or `internal_error`.
     * **Ignored:** Non-code files (`.md`, `.json`, `.yml`, lockfiles, `.html`/`.htm`), `deleted` entries returned by `git diff` in `modified` mode, and `excluded_path` entries touched in `git diff` (`modified` mode, rendered as `- Ignored (excluded path): N` when `N > 0`). Missing explicit CLI file paths and invalid `fail_on_unanalyzable` values write `overall_score=N/A` and `audit_status=FAIL` to `GITHUB_OUTPUT` before exiting `1`.
   * **Fail-Closed Analysis Errors:** If an individual file raises a `parse_error` or `internal_error` during classification/audit (or triggers a runtime coverage invariant mismatch), remaining analyzed files still run for visibility, **but the overall gate fails closed** (`audit_status=FAIL`, `exit 1`, and SARIF `runs[0].invocations[0].executionSuccessful=false` with `level: "error"` notifications), even when `fail_on_unanalyzable` is `'false'`.
   * **`N/A` Score for Zero Analyzed Files & Numeric Consumers:** When `analyzed === 0` (for example, a PR modifying only `.go` or `.md` files), `overall_score` in `GITHUB_OUTPUT` and the sticky PR comment is reported as the literal string **`N/A`** (never `100/100`), the `min_score` comparison is skipped, and the gate passes (`exit 0`) unless `fail_on_unanalyzable` is `'true'` with `skipped > 0` or an analysis error occurred. **Downstream workflow consumers parsing `steps.<id>.outputs.overall_score` numerically must handle the string `N/A` explicitly.**
   * **PR Status Badges (Evaluated in Strict Priority Order):**
     1. `🚫 REJECTED (SECURITY GATE FAILED)` — an analyzed file failed `min_score`, security floor, or error-level findings.
     2. `🚫 REJECTED (ANALYSIS ERROR)` — `parse_error`, `internal_error`, or coverage invariant mismatch occurred.
     3. `🚫 REJECTED (UNANALYZED FILES)` — `fail_on_unanalyzable: 'true'` and `skipped > 0`.
     4. `⚠️ NOT ANALYZED — no supported code files` — `analyzed === 0` (exit `0` when no analysis/strict errors).
     5. `⚠️ PARTIALLY ANALYZED — language-agnostic rules only` — `analyzed > 0` and every analyzed file is `partial` (`.py` only; exit `0` when passing thresholds).
     6. `✅ PASSED (READY TO MERGE)` — full JS/TS coverage (or mixed JS/TS + `.py`) passed all checks.
   * **Strict `fail_on_unanalyzable` Parsing & SARIF:** `DEVGUARD_FAIL_ON_UNANALYZABLE` accepts strictly `'true'`, `'false'`, or empty/unset (trimmed, case-insensitive, without `INPUT_*` fallback); invalid values (such as `'yes'`, `'1'`, `'ture'`) fail immediately with `exit 1`. Partial (`level: "note"`), skipped (`level: "note"`), `fold_limit_exceeded` (`level: "note"`), and error (`level: "error"`) notifications are written to `runs[0].invocations[0].toolExecutionNotifications[]` in `devguard-results.sarif` without altering `results[]`.

### Exact Escalation Criteria & v1.3.0 Evasion Patterns (`DG005`, `DG008`, `DG004-DYN-01/02`)
* **`DG005` (`warning` → `error`) & Shared `CRITICAL_FLOW_IDENTIFIERS`:**
  * **Default (`warning`):** Empty or `console.*`-only `catch` block in non-critical flows deducts `-10` `maintainability` (excluding cleanup calls like `unlink`/`rmSync`/`close` and `JSON.parse` fallbacks).
  * **Escalated (`error`):** When the `try` body matches the single exported `CRITICAL_FLOW_IDENTIFIERS` list (`payment`, `balance`, `wallet`, `ledger`, `transfer`, `charge`, `refund`, `deduct`, `invoice`, `auth`, `token`, `jwt`, `password`, `execute`, `query`, `transaction`, `writeFileSync`), `DG005` escalates to `error`, deducts `-20` `security` (`isCritical: true`) + `-15` `correctness`, provides an inline rethrow `suggestion`, and becomes non-suppressible inline.
  * **`DG005-EV-01` (Empty Promise `.catch()` on Critical Receiver Chains, `warning`):** Detects `.catch(() => {})`, `_ => {}`, `(e) => {}`, `function () {}` on receiver backbones matching `CRITICAL_FLOW_IDENTIFIERS` (deducting `-10` `maintainability`, suppressible inline via `DG005` or `DG005-EV-01`). Backward receiver-chain parsing skips call arguments (e.g., `fetch(url, { headers: { token } }).catch(() => {})` is safe) and limits cleanup exemptions (`unlink`, `rmSync`, `close`, `JSON.parse`) strictly to the call immediately preceding `.catch` (so `pay.charge(x).then(() => fs.unlink(tmp)).catch(() => {})` still triggers).
* **`DG008` (`warning` → `error`) & `DG008-EV-01`:**
  * **Default (`warning`):** External `fetch()` calls lacking `signal`, `AbortSignal.timeout()`, or an enclosing `AbortController` (excluding local mock hosts `127.0.0.1`, `localhost`, `[::1]`) emit `warning` with `-10` `correctness`.
  * **`DG008-EV-01` (`do { ... } while (true | 1)`, `warning`):** Shares the same unbounded loop body inspector (`await` present without `break`, `return`, `throw`, `process.exit`, or bounded retry check) as `while`/`for`, deducting `-10` `correctness` while rejecting `.do()` member calls and standalone `{ ... } while (true) { ... }` blocks.
  * **Escalated (`error`):** Emits `error` whenever:
    1. An unbounded `while (true)`, `while (1)`, or `for (;;)` loop contains `await` without `break`, `return`, `throw`, `process.exit`, or a bounded retry check (`-25` `correctness`, `isCritical: true`), **or**
    2. A timeout-less `fetch()` targets a critical API/payment gateway (`openai`, `gemini`, `generativelanguage`, `anthropic`, `deepseek`, `radeon`, `stripe`, `payment`, `webhook`, `charge`, `verify`), deducting `-20` `security` (`isCritical: true`).
* **`DG004-DYN-01` & `DG004-DYN-02` (`warning`, `properties.scoring: false`):**
  * Flags non-literal dynamic `import(expr)` and `require(expr)` specifiers while excluding property calls (`obj.require`), method declarations (`class C { require() {} }`), zero-argument calls, and comments/strings/regexes. If a local `require` identifier is shadowed (`const require = ...` or `function require(...)`), `DG004-DYN-02` conservatively skips that file and records `dynScopeUncertain`.

---

## 🔒 Non-Bypassable Suppression Policy & Base-Branch Allowlist

DevGuard supports controlled suppressions without letting AI-generated Pull Requests silently weaken critical security gates.

| Rule ID | Severity | Inline Suppression (`// devguard-ignore`) | `.devguard.json` Base-Branch Allowlist | Notes |
| :--- | :---: | :---: | :---: | :--- |
| **`DG001`** | `error` | ❌ Forbidden | ❌ Forbidden | Critical RCE/injection/traversal findings remain active with bypass warning |
| **`DG002`** | `warning` | ❌ Forbidden | ❌ Forbidden | Score/defense-in-depth notes are never suppressible |
| **`DG003`** | `error` | ❌ Forbidden | ❌ Forbidden | Score gate failures are never suppressible |
| **`DG004`** | `error` | ❌ Forbidden | ✅ Allowed (base branch only) | For monorepo/hoisted or vendored packages (base-branch `.devguard.json` only) |
| **`DG004-DYN-01` / `02`** | `warning` (`non-scoring`) | ❌ Forbidden | ✅ Allowed (base branch only) | Supports linear-time glob matching (`matchLinearGlob`); direct or `DG004` allowlist applies |
| **`DG005`** / **`DG005-EV-01`** | `warning` | ✅ Allowed (`>= 8` chars, 2+ words) | ❌ Forbidden | Non-critical `catch` & `DG005-EV-01` `.catch()` warnings may be suppressed via `DG005` or `DG005-EV-01` |
| **`DG005`** | `error` | ❌ Forbidden | ❌ Forbidden | Critical auth/payment/DB `error` catches cannot be suppressed |
| **`DG006`** | `error` | ❌ Forbidden | ✅ Allowed (base branch only) | External distributed locks can allowlist specific files on base branch |
| **`DG007`** | `error` | ❌ Forbidden | ❌ Forbidden | Hardcoded secret exposure cannot be suppressed |
| **`DG008`** / **`DG008-EV-01`** | `warning` / `error` | ✅ Allowed (`>= 8` chars, 2+ words) | ❌ Forbidden | Supports both `// devguard-ignore DG008: ...` and `// devguard-ignore DG008-EV-01: ...` |

### Lexer-Level Inline Suppressions
* Inline comments must be real `//` or `/* ... */` comments (not inside strings, template literals, or regex literals) immediately above or trailing the flagged line (including lines remapped from `Pass-V` folds):
  ```ts
  // devguard-ignore DG008: upstream AbortController enforces gateway deadline
  const response = await fetch('https://api.example.com/health');
  ```
* A meaningful justification reason of at least **8 characters** containing **at least two alphabetic words** (`/[A-Za-z]{2,}\s+[A-Za-z]{2,}/`) after `DGxxx:` is mandatory; dummy padding such as `"xxxxxxxx"` or `"........"` is rejected.
* Attempting inline suppression on forbidden rules (`DG001`, `DG004`, `DG004-DYN-01/02`, `DG005` `error`, `DG006`, `DG007`) leaves the finding active and appends `[Suppression ignored: DGxxx cannot be suppressed inline]`.

### Verified `.devguard.json` Allowlist Security Model
* **Strict Base-Branch Loading in CI:**
  * On Pull Requests (`GITHUB_BASE_REF`), DevGuard reads `.devguard.json` **strictly from git history** via `git show origin/${GITHUB_BASE_REF}:.devguard.json`.
  * On `push` events with a valid non-zero `before` SHA, DevGuard reads `${beforeSha}:.devguard.json`.
  * **PR edits to `.devguard.json` do NOT apply to the current PR**; they take effect **only after merge** into the base branch, and a warning banner is posted in the sticky PR comment whenever `.devguard.json` changed in the PR.
* **Validation Constraints & Linear-Time Globs (`matchLinearGlob`):** `DG004`, `DG004-DYN-01`, `DG004-DYN-02`, and `DG006` are permitted under `ignoreRulesByPath`, each entry requires a trimmed `reason` of length `>= 8` with at least two alphabetic words (`/[A-Za-z]{2,}\s+[A-Za-z]{2,}/`), patterns above `MAX_GLOB_PATTERN_LENGTH = 256` or pathological bare wildcards (`*`, `**`, `/*`, `../`, leading `/`) are rejected, and matching runs in linear DP time without ReDoS backtracking.
* **Monorepo Workspace Resolver Configuration (`workspaces.mode` & `256 KiB` Size Limit):**
  * `.devguard.json` supports an optional `"workspaces": { "mode": "auto" | "off" }` object (read from the base branch in CI, defaulting to `"auto"`). Setting `"mode": "off"` disables workspace resolution and restores exact `v1.3.0` behavior as an escape hatch; invalid `mode` values or unknown keys fail closed to `"off"`.
  * All workspace configuration files (`package.json`, `pnpm-workspace.yaml`, `tsconfig.json`) are strictly capped at **`256 KiB`** (`MAX_CONFIG_FILE_SIZE = 256 * 1024` bytes in `src/rules/workspaceParser.ts`). Any config exceeding this limit fails closed per source with a non-scoring `DG004-WS-UNPARSED` notice (`reason: "size_limit"`), contributing zero partial package names.
* **SARIF Audit Trail:** Active `inSource` and `external` suppressions are recorded on the PR summary table and emitted into `devguard-results.sarif` using standard OASIS `suppressions` metadata (`kind`, `justification`).

---

## 🔐 Layer 2 Pre-LLM Secret Redaction & Credential Rotation

Before transmitting any snippet to the Gemini REST endpoint (`generativelanguage.googleapis.com`), `prepareRedactedCodeForLlm` enforces a strict fail-closed privacy gate:

1. **Sensitive Filename Blocking (Case-Insensitive):** Immediately aborts Layer 2 (`Skipped: Redaction Abort`) without network calls for files matching:
   * `^\.env(\..+)?$` (e.g., `.env`, `.env.local`, `.ENV.PRODUCTION`) and `^\.(npmrc|netrc|pgpass)$`
   * `\.(pem|key|p12|pfx|crt|tfvars|tfstate|jks|keystore)$`
   * `^id_(rsa|ed25519|ecdsa)(\..+)?$` and `^kubeconfig(\..+)?$`
   * `(?:credentials|service-account).*\.json$`
2. **Layout-Preserving Secret Redaction (`redactSecretsPreservingLayout`):** Replaces PEM private key blocks, credentialed DB URI passwords, JWTs, `DG007` provider prefixes, and high-entropy secret string literals with `*` while preserving exact UTF-16 string length, `\n`, `\r`, and `\t` indices so line numbers stay aligned (including findings remapped from `Pass-V`), and passes the Gemini API key in the `x-goog-api-key` request header instead of URL query strings.
3. **Independent Residual Entropy Gate (`findResidualSecretLikeTokens`):** Re-scans redacted output independently (without reusing `DG007` provider regexes) for surviving PEM headers, unmasked URI credentials, or 24–256 character tokens having `>= 3` character classes and Shannon entropy `>= 4.2` bits/char (excluding URLs, `data:*base64,`, and asset file paths). If **any** residual finding or unexpected error occurs, Layer 2 aborts fail-closed (`Layer 2 (Gemini): Skipped [Redaction Abort]`) and Layer 1 continues offline.

> [!CAUTION]
> **Rotate Leaked Credentials Immediately:** Automated secret redaction prevents sending secrets to Layer 2 Gemini and masks `DG007` PR comment/SARIF outputs, **but removing or masking a secret in source code does not remove it from Git commit history**. Any credential detected by `DG007` must be revoked and rotated immediately at the provider.

---

## 🛡️ Fork PR Safety, Fail-Open Commenting, & Workflow Security

* **Upfront Fork PR Detection (`detectPrEnvironment`):** Inspects `GITHUB_EVENT_PATH` and marks a Pull Request as a fork (`isFork = true`) whenever `head.repo` is `null` (deleted fork), repo metadata is missing, or `pull_request.head.repo.full_name !== repository.full_name`.
* **Zero-Secret Fork Execution:** When `isFork === true`, Layer 2 Gemini network calls are skipped automatically (`Layer 2 (Gemini): Skipped [Fork PR]`).
* **Fail-Open PR Commenting & Exit-Code Integrity:** HTTP `403` (read-only fork token) and HTTP `422` (line outside diff hunk) responses during sticky summary or inline review API calls degrade gracefully to console warnings and **never alter the CLI exit code** (`1` when findings fail the gate, `0` when clean).
* **Explicit Layer 2 Status Transparency:** Both the sticky PR header and per-file table display the exact analysis state:
  * `Layer 2 (Gemini): Verified`
  * `Layer 2 (Gemini): Skipped [Offline | No API Key | Fork PR | Quota/Error Fallback | Redaction Abort]`

> [!WARNING]
> **Never Use `pull_request_target`:** Always run DevGuard under `pull_request` (never `pull_request_target` — DevGuard exits immediately with code `1` if `GITHUB_EVENT_NAME == 'pull_request_target'`), which checks out untrusted fork code in an isolated context without write tokens or repository secrets. Guard `upload-sarif` with `if: always() && (github.event_name != 'pull_request' || (github.event.pull_request.head.repo != null && github.event.pull_request.head.repo.full_name == github.repository))` so fork PRs never fail a job step attempting unauthorized SARIF uploads.
>
> **Enable Branch Protection:** Configure GitHub branch protection / rulesets with **Require status checks to pass before merging** for `DevGuard Quality Gate` so Pull Requests cannot bypass or delete `.github/workflows/devguard.yml`.

---

## 🏗️ Hybrid Dual-Layer Architecture

1. **Layer 1 — Deterministic Lexical, Constant-Folding (`Pass-V`), & Heuristic Engine (`Zero-Dependency`):**
   * Core analyzers ([src/devguardAnalyzer.ts](src/devguardAnalyzer.ts), [src/rules/lexicalMasker.ts](src/rules/lexicalMasker.ts), [src/rules/spanMap.ts](src/rules/spanMap.ts), [src/rules/packageAndExceptionRules.ts](src/rules/packageAndExceptionRules.ts), and [src/rules/secretAndResilienceRules.ts](src/rules/secretAndResilienceRules.ts)) are browser-safe TypeScript modules; CLI & GitHub integration use only Node.js built-ins (`node:fs`, `node:path`, `node:child_process`, `node:module`, `node:os`) and native `fetch()`.
   * Immune to prompt-injection instructions embedded in comments (`// IGNORE ALL PREVIOUS INSTRUCTIONS`).
   * Cross-checks imported packages and `#subpath` aliases against ancestor `package.json` manifests and Node built-ins without external registry latency.
2. **Layer 2 — Gemini Adversarial Reasoning (`Fail-Closed Privacy` + `Fail-Open Resilience`):**
   * Uses a direct zero-dependency `fetch()` POST request to `generativelanguage.googleapis.com` with the `x-goog-api-key` header when running on same-repo workflows with a valid `AIzaSy...` key and after passing the Pre-LLM redaction & residual entropy gate.
   * Caps Layer 2 score deductions against clean Layer 1 verdicts so unverified LLM prose alone cannot fail a clean PR, and degrades fail-open to Layer 1 scores on timeout (`6.5s`), HTTP 4xx/5xx errors, or redaction aborts without breaking CI.
3. **One-Click PR Inline Remediation, Sticky Summary, & SARIF v2.1.0:**
   * Posts deduplicated inline review `suggestion` blocks per `path:line:ruleId` (capping `DG004-DYN-*` inline comments at `MAX_DYN_FINDINGS_PER_FILE = 20`) and maintains a single sticky PR summary table with Active Suppressions, Rejected Allowlist Entries, and explicit Layer 2 status badges (with `@mentions` and external markdown images neutralized).
   * Writes OASIS SARIF v2.1.0 logs with GitHub Code Scanning `security-severity` ratings (`3.5`–`9.5`), `%SRCROOT%` forward-slash relative URIs, unclipped non-scoring `DG004-DYN-*` warnings (`properties.scoring=false`), standard `suppressions` records without custom `partialFingerprints`, and `toolExecutionNotifications[]` (`fold_limit_exceeded`, partial `.py`, skipped/error).

---

## 📊 Benchmark Corpus, Performance Gate, External OSS Validation, & Known Limitations

DevGuard tracks detector precision, recall, and remaining evasion boundaries transparently in [tests/corpus/cases.ts](tests/corpus/cases.ts) (`npm run corpus:report`). Because Layer 1 operates deterministically without inter-procedural symbolic execution or arbitrary control-flow analysis, multi-hop variable aliasing (`const fn = eval`) and indirect helper indirection remain explicitly documented as `knownMiss` cases below.

### Automated Corpus Benchmark (`n = 129`, `v1.3.0`)
- **Total Curated Cases:** `n = 129` (`TP = 48`, `TN = 63`, `EVASION = 18`, `knownMiss = 8`, `knownFP = 0`)
- **Curated Corpus TN Guarantee:** All `63/63` negative cases in the labeled test corpus produce `0` findings across all rules (`DG001`–`DG008`, `DG004-DYN-01/02`, `DG005-EV-01`, `DG008-EV-01`). (See the External OSS Validation table below for observed real-world false positives, especially `DG004` in monorepos.)

| Rule | TP (hit/total) | TN (FP/total) | EVASION (hit/total) | knownMiss | knownFP |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `DG001` | `8/8` | `0/10` | `2/3` | `1` | `0` |
| `DG004` | `7/7` | `0/8` | `2/3` | `1` | `0` |
| `DG004-DYN-01` | `3/3` | `0/5` | `0/0` | `0` | `0` |
| `DG004-DYN-02` | `3/3` | `0/6` | `0/0` | `0` | `0` |
| `DG005` | `7/7` | `0/10` | `1/3` | `2` | `0` |
| `DG006` | `6/6` | `0/6` | `1/3` | `2` | `0` |
| `DG007` | `7/7` | `0/9` | `3/3` | `0` | `0` |
| `DG008` | `7/7` | `0/9` | `1/3` | `2` | `0` |

#### Pass-O vs Pass-O+V Performance & Scale Benchmarks (`Tests 70 & 80`, Node `v26.13.0` Windows Host)
* **Full Corpus (`129` cases, median of 25 iterations after warmup, `Test 70`):** `Pass-O Only = 160.47 ms` (`1.244 ms/case`) vs `Pass-O+V = 172.18 ms` (`1.335 ms/case`, **`+7.30%` overhead**, within the `SPEC.md` §9 `<= +25%` gate).
* **Non-Fold Baseline Subset (`108` cases with `editsApplied === 0`, `Test 70`):** `Pass-O Only = 134.30 ms` vs `Pass-O+V = 134.33 ms` (**`+0.02%` overhead**, `749 cases/sec`).
* **Single-File Scaling & 1 MB Worst-Case Stress (`Test 80`):**

| Workload | File Size | `Pass-O` Time | `Pass-O+V` Time | Latency Delta | Heap Delta | Folds Applied |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Large Module (`100 KB`) | `99 KB` | `40.82 ms` | `69.85 ms` | `+29.03 ms` | `+10.03 MB` | `62` |
| Large Module (`250 KB`) | `248 KB` | `67.64 ms` | `175.33 ms` | `+107.68 ms` | `+7.94 MB` | `156` |
| Large Module (`500 KB`) | `499 KB` | `131.06 ms` | `284.07 ms` | `+153.01 ms` | `+23.18 MB` | `313` |
| Max Analysis Limit (`1 MB`) | `999 KB` | `252.62 ms` | `509.79 ms` | `+257.17 ms` | `+51.05 MB` | `627` |
| Dense Fold Stress (`1 MB Worst-Case`) | `1000 KB` | `327.44 ms` | `1199.84 ms` | `+872.40 ms` | `-27.66 MB`* | `2000` (capped) |

*\*Negative heap delta reflects V8 garbage collection occurring during the unforced memory measurement.*

#### Remaining Documented `knownMiss` Corpus Cases (`n = 8`, `0` in `v1.3.0` Scope)
Compared to `v1.2.1` (`14 knownMiss`), **`v1.3.0` resolved 6 documented evasion cases** (`DG004-EV-02` via `Pass-V`, `DG005-EV-01` via empty `.catch()` detector, `DG006-EV-01` via `FOLD-04`, `DG007-EV-01` & `DG007-EV-03` via `FOLD-01`/`02`, and `DG008-EV-01` via `do...while(true|1)`). The remaining `8` cases intentionally sit outside Stage 5 lexical/single-statement scope (inter-statement or inter-procedural aliasing):
- **`DG001-EV-03`** (`DG001`, `knownMiss`): Split string bracket lookup assigned to an intermediate alias (`const fn = (globalThis as ...)['ev' + 'al']; return fn(payload);`) — now surfaced non-scoring by **`DG001-ALIAS-01`** via `Pass-V` + intra-procedural alias tracking while remaining `knownMiss` for scoring `DG001` until external corpus promotion (`INV-8`).
- **`DG004-EV-01`** (`DG004`, `knownMiss`): Dynamic `import(variable)` is now surfaced non-scoring by **`DG004-DYN-01`** while remaining an intentional `knownMiss` for scoring `DG004` slopsquatting.
- **`DG005-EV-02`** (`DG005`, `knownMiss`): `catch` delegates to a separate no-op helper (`ignore()`) instead of an empty block or `console.*`.
- **`DG005-EV-03`** (`DG005`, `knownMiss`): Dead variable assignment inside `catch` suppresses empty-catch check.
- **`DG006-EV-02`** (`DG006`, `knownMiss`): Aliased variable compare (`available >= amount`) before awaiting and mutating `account.balance`.
- **`DG006-EV-03`** (`DG006`, `knownMiss`): Check and `await`+mutation separated by more than 25 lines.
- **`DG008-EV-02`** (`DG008`, `knownMiss`): Aliased `fetch` reference (`const httpGet = fetch`) bypasses literal `fetch()` call matcher.
- **`DG008-EV-03`** (`DG008`, `knownMiss`): `while (running)` async loop where boolean guard is never mutated or broken.

#### External Real-World OSS Repository Validation (`n = 10` Convenience Sample, `4,318` Analyzed Files)
Validated offline (`DEVGUARD_TARGET=all`, `GEMINI_API_KEY=""`, zero temp artifacts left in repo) against shallow clones (`--depth 1`) of 10 production JS/TS repositories in `os.tmpdir()`. *(Because this `n = 10` cohort is a convenience sample rather than a random statistical cross-section, results illustrate ecosystem behavior and failure modes rather than universal precision rates.)*

| Repository | Commit SHA | Ecosystem | Analyzed / Skipped | Wall-Clock Time | Findings Summary | Audit Observations |
| :--- | :--- | :--- | :---: | :---: | :--- | :--- |
| **`sindresorhus/ky`** | `3541888` | HTTP / ESM TS | `98` / `0` | `662.5 ms` | `DG004`: `21`, `DG005`: `3`, `DG008`: `285`, `fold_limit`: `2` | `0` crashes; `DG004` flags self-imports (`'ky'`) inside `test-d/`; confirmed `catch {}` (`source/core/Ky.ts:107`) |
| **`colinhacks/zod`** | `e32e088` | Monorepo / TS | `307` / `1` | `3,729.2 ms` | `DG001`: `1`, `DG004-DYN-01`: `1`, `DG005`: `31`, `DG008`: `1` | `0` crashes; `DG001` (`packages/bench/memory/dict-mode.ts:13` `eval(...)`) & `DG004-DYN-01` (`benchUtil.ts:5`) accurate |
| **`expressjs/express`** | `43fca52` | Backend / CJS | `142` / `0` | `1,540.9 ms` | `DG004-DYN-02`: `3`, `DG004`: `3` | `0` crashes; `DG004-DYN-02` accurately surfaced dynamic `require(path/file/mod)` loaders |
| **`fastify/fastify`** | `825d772` | Backend / CJS | `85` / `1` | `767.8 ms` | `0` findings | `0` crashes, `0` false positives |
| **`honojs/hono`** | `75ff8e3` | Edge / TS | `290` / `1` | `2,591.6 ms` | `DG004-DYN-01`: `3`, `DG005`: `14`, `DG008`: `2`, `DG004`: `1` | `0` crashes; `0` observed FPs in sampled `DG004-DYN-01` results |
| **`vercel/swr`** | `8148ef0` | React / Next.js | `213` / `0` | `1,829.0 ms` | `DG008`: `35`, `DG004`: `1`, `DG005`: `2` | `0` crashes; `DG008` reflects test/runtime `fetch` without `AbortSignal.timeout()` |
| **`vitejs/vite`** | `ef295d5` | Build / Monorepo | `1,452` / `13` | `14,987.4 ms` | `DG001`: `3` *(down from `4`)*, `DG004`: `48`, `DG005`: `30`, `DG004-DYN-01`: `57`, `DG004-DYN-02`: `1`, `DG008`: `7` | Fixed Playwright `page.$eval()` FP (`4 -> 3`); `DG004` flags monorepo aliases, self-imports & `preact` typosquat FPs |
| **`nestjs/nest`** | `bbbfaf1` | Enterprise / TS | `1,682` / `0` | `14,429.3 ms` | `DG001`: `0` *(down from `1`)*, `DG004`: `481`, `DG008`: `10`, `DG004-DYN-01`: `5`, `DG005`: `13` | Fixed `async exec()` method-decl FP (`1 -> 0`); heavy `DG004` workspace/monorepo package FPs (`481`) |
| **`tj/commander.js`** | `a5a7dc0` | CLI Tooling | `46` / `8` | `367.1 ms` | `DG004`: `39` | `0` crashes; `DG004` flags workspace self-package imports |
| **`electron/electron-quick-start`** | `de47e7e` | Desktop / Electron | `3` / `0` | `26.3 ms` | `0` findings | `0` crashes, `0` false positives |

* **Key OSS Validation Takeaways:** Across `4,318` analyzed files (`0` `analysisFailures`), `DG004-DYN-01/02`, `DG005-EV-01`, `DG008-EV-01`, and `[via-fold]` produced `0` observed false positives in manually inspected findings. However, **`DG004` emits substantial false positives in monorepos and workspace packages** (`481` in NestJS, `48` in Vite, `39` in Commander.js, `21` in Ky `test-d/`), requiring base-branch `.devguard.json` allowlists in monorepo setups; two real-world `DG001` FPs (`page.$eval` and `async exec() {}`) were also identified and eliminated during this validation pass.

See also [docs/benchmarks/realworld-2026-11-16.md](docs/benchmarks/realworld-2026-11-16.md) for the initial DevGuard `src/` self-scan baseline (`7` files under `src`, `0` false-positive findings across `DG001`–`DG008`).

### Known Limitations (Path Exclusions, CLI Scope, & Monorepo `pnpm strict`)
* **Path Exclusions by Mode (`modified` vs. `all`):** Dot-prefixed paths (`.github/`, `.husky/`), `node_modules`, `dist`, `build`, `coverage`, `remotion`, `out`, `tests`, all files inside `scripts/`, anchored self-reference files (`src/devguardAnalyzer.ts`, `scripts/devguard_verify.py`, `devguard_verify.py` when `package.json` `"name": "devguard"`), `*.d.ts`, `*.test.*`, and `*.spec.*` are excluded from code auditing. In `modified` (`git diff`) mode, touched excluded paths enter the classifier as `ignored/excluded_path` and appear in PR Coverage as `- Ignored (excluded path): N` when `N > 0` so the coverage invariant covers 100% of `git diff`. In `all` mode, excluded directories are skipped during workspace traversal so `node_modules` is never walked.
* **Explicit CLI Arguments & `--version`:** Explicit file arguments passed on the CLI follow the coverage classifier (`.py` is analyzed with `partial` coverage; unsupported extensions like `.go` are marked `skipped`). Missing explicit CLI paths and invalid `fail_on_unanalyzable` values write `overall_score=N/A` and `audit_status=FAIL` to `GITHUB_OUTPUT` before exiting `1` rather than counting as `ignored/deleted`. Passing `--version` or `-v` prints the resolved package version (e.g. `1.6.0`) and exits `0`.
* **Monorepo `pnpm strict` Non-Hoisting Limitation (`SPEC §6.2a`):** On `pnpm` repositories that disable dependency hoisting, importing a dependency declared only in the repository root `package.json` from a nested workspace package will fail at runtime under strict `pnpm`, whereas DevGuard resolves it as `resolvedVia: root` for cross-mode determinism (`DG004` detects fictitious/hallucinated package names, and root-declared packages are real dependencies). Intermediate ancestor manifests and sibling package dependencies are never merged (`A6-9`, `A6-12`).
* **Shallow Clone (`fetch-depth: 1`) Base-Ref Fallback & Notice (`[DG004-WS-SHALLOW]`):** When CI runs with default `fetch-depth: 1` and `origin/<baseRef>` cannot be fetched, DevGuard fails closed to `0` admitted base workspace packages (preventing PR-injected bypasses) and surfaces an explicit non-scoring `[DG004-WS-SHALLOW]` notice in the sticky PR comment reminding developers to configure `fetch-depth: 0` on `actions/checkout@v4`.
* **MCP Server Read-Only Scope (`SPEC §8.3`):** `devguard mcp` is intentionally read-only and offline in `v1.6.0` (no auto-fix file writes, no shell execution, no network calls). `devguard_check_snippet` runs in single-file mode (`workspacesMode: 'off'`) without monorepo workspace resolution; use `devguard_check_files` for workspace-aware audits. Core `defenseInDepth` advisory strings remain in their original Indonesian phrasing inside `files[].defenseInDepth` while MCP protocol/error/boundary metadata is English.

### Behavior Changes from `v1.5.0` to `v1.6.0`
* **Zero-Dependency MCP Server (`src/adapters/mcp/`, SPEC Stage 8):** Added `devguard mcp [--workspace <dir>]` implementing a custom stdio JSON-RPC 2.0 server with strict `initialize` protocol version negotiation (`2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`) and three read-only tools (`devguard_check_files`, `devguard_check_snippet`, `devguard_explain_rule`), verified end-to-end with `@modelcontextprotocol/inspector@0.16.8` (`A8-1`–`A8-5`).
* **MCP Security Controls (`SPEC §8.3`):** Enforces fail-closed workspace path jailing (`resolveJailedWorkspacePath`), prompt-injection isolation (`quoted_source` + `security_boundary`), secret redaction (`INV-3`), `1 MiB` streaming stdin buffer capping with mid-stream discard, and `512 KiB` structured JSON output bounding.
* **Audit Waves 1–3 Hardening:** Enforced Pre-LLM redaction gate and `1 MiB` cap on `/api/devguard/review`, purified CLI `--format sarif` stdout, added NUL-safe git diff parsing (`-z`, `core.quotePath=false`), strict CLI flag value validation (`exit 2` on I/O & flag errors), TOCTOU comment-bypass defense (`DG006`), `DG003` threshold parity, `residualNotes` preservation, and multi-line `Pass-V` remapping (`Tests 92–93`).

### Behavior Changes from `v1.4.0` to `v1.5.0`
* **Headless Core Engine Architecture (`src/core/`, SPEC Stage 7):** Full separation of analyzer core logic (`src/core/analyzer.ts`), rule suites (`src/core/rules/`), types (`src/core/types.ts`), and SARIF formatting (`src/core/sarif.ts`) from GitHub Action runtime, verified with byte-for-byte SARIF parity (`Test 88`).
* **Standalone Zero-Dependency CLI (`src/adapters/cli/`):** Run audits anywhere locally with `devguard check [<paths>...]` supporting `--staged`, `--changed-since=<ref>`, `--format=text|json|sarif`, `--min-score=<n>`, `--config=<path>`, `--fail-on-unanalyzable`. Features strict argument injection defense (`--` separator, ref validation) and offline-by-default Layer 2 operation (`Skipped [Offline]`).
* **Idempotent Git Pre-Commit Hook Installer (`devguard install-hook`):** Automatically wires zero-dependency pre-commit checks dynamically into `.git/hooks/pre-commit` (supporting worktrees via `git rev-parse --git-path hooks`) with safe marker blocks (`# BEGIN DEVGUARD HOOK`) and multi-tier runtime fallback (`devguard` -> `./dist/cli.js` -> `npx --no-install devguard`).
* **`npx` Packaging & Dual Entrypoints:** Bundles standalone zero-dependency executable CLI at `dist/cli.js` via `esbuild` with `"bin": { "devguard": "./dist/cli.js" }` and `"files": ["dist/cli.js", "README.md"]`.
* **Zero-Dep Bilingual UI Toggle (`src/i18n.ts`):** Added strongly-typed `EN` / `ID` language switcher in the local dashboard header without external runtime dependencies.

### Behavior Changes from `v1.3.0` to `v1.4.0`
* **DG004 Monorepo Workspace Resolver (`SPEC-v1.4.md` rev 1.3):** Full zero-dependency resolution for monorepos (pnpm workspaces, npm/Yarn workspaces, Bun workspaces, and TypeScript path aliases via `tsconfig.json` `paths` / `baseUrl` and Node `#subpath` imports). Resolves packages via strict precedence (`nearest` → `root` → `workspace` → `tsconfig`/`#imports`), dramatically reducing monorepo false positives across real-world codebases (`nestjs/nest` 481 → 8, `tj/commander.js` 39 → 3, `vitejs/vite` 59 → 55).
* **Safe Skip of Non-`packages:` Top-Level YAML Keys:** Safely skips top-level pnpm v10+ keys (`hoistPattern:`, `shellEmulator:`, etc.) in `pnpm-workspace.yaml` without breaking package parsing, while keeping unsupported YAML constructs fail-closed (`DG004-WS-UNPARSED`).
* **Base-Branch Configuration Gate:** `.devguard.json` supports `"workspaces": { "mode": "auto" | "off" }` read strictly from base-branch git history; untrusted PR modifications cannot alter workspace mode.
* **Shallow Clone Warning:** Emits explicit non-scoring `[DG004-WS-SHALLOW]` sticky comment guidance when `fetch-depth: 1` prevents base-branch resolution.

---

## 🧪 Local Development & Verification

DevGuard enforces a strict zero-dependency test harness using Node's built-in assertion & test runner (`node:test` compiled via `tsconfig.test.json` and executed in-process), currently verified at **95 passing test scenarios** across [tests/corpus.test.ts](tests/corpus.test.ts) (`Corpus Benchmark`) and [tests/integration.test.ts](tests/integration.test.ts) (`Tests 1–94`):

```bash
# 1. Typecheck application, CLI, & tests
npm run lint

# 2. Build standalone web UI bundle & CLI binary (dist/cli.js)
npm run build

# 3. Run zero-dependency benchmark + integration test suite (94 passing scenarios)
npm test

# 4. Print DevGuard CLI version cleanly
node dist/cli.js --version

# 5. Run standalone CLI check on staged files
node dist/cli.js check --staged

# 6. Regenerate labeled corpus Markdown summary
npm run corpus:report
```

---

## 📄 License

MIT License — Built for developers shipping fast with AI without sacrificing production security.
