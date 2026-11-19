# 🛡️ DevGuard v1.3.0 — The AI-Slop & Vibe-Coding Security Gatekeeper

[![Zero-Dependency Runtime](https://img.shields.io/badge/Runtime-100%25%20Zero--Dependency-emerald.svg)](#hybrid-dual-layer-architecture)
[![OASIS SARIF v2.1.0](https://img.shields.io/badge/SARIF-v2.1.0%20Compliant-blue.svg)](#quick-start-fork-safe-ci-setup)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-v1.3.0-black.svg)](#quick-start-fork-safe-ci-setup)
[![Tests 75/75 Passing](https://img.shields.io/badge/Tests-75%2F75%20Passing-success.svg)](#local-development--verification)

**DevGuard** is a deterministic CI/CD security gatekeeper engineered to catch silent failures, slopsquatting, leaked API keys, and financial race conditions hidden inside AI-generated (*Cursor, Windsurf, Copilot, Antigravity*) Pull Requests before they reach production.

Unlike generic LLM code reviewers that only leave probabilistic chat comments, DevGuard combines a **0-latency Deterministic Single-Pass Lexical & Heuristic Engine** (`Pass-O` + additive `Pass-V` virtual constant folding) with optional **Gemini Adversarial Reasoning**, posts **One-Click GitHub Suggested Changes** directly on offending diff lines, and uploads **OASIS SARIF v2.1.0** reports to GitHub Code Scanning.

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
   * When `editsApplied === 0`, DevGuard pays **zero `Pass-V` overhead** and produces identical results to `Pass-O`.
   * When `editsApplied > 0`, detectors re-run on virtual code `V`, map every line/span back to original source `O` via binary-search `toOrigLineAndCol` / `toOrigSpan` (`SpanMap`), deduplicate against `Pass-O`, apply suppressions on original lines `O`, and tag virtual-only findings with `[via-fold]`.
   * `DG004-DYN-01/02` runs in `virtual-only` mode whenever `editsApplied > 0`, automatically silencing spurious dynamic-specifier warnings on statically resolvable concatenations such as `require("node:p" + "ath")`.
3. **Deterministic DoS Bounds & SARIF Visibility:**
   * Hard-capped at `MAX_FOLD_DEPTH = 4`, `MAX_FOLD_OPERANDS = 64`, `MAX_FOLDED_LENGTH = 4096`, `MAX_FOLD_EDITS = 2000`, and `MAX_BACKSCAN = 256` with non-overlapping monotonic `SpanMap` invariants verified by property tests.
   * Files hitting fold limits degrade safely with partial folds and emit a deduplicated `level: "note"` notification (`descriptor.id: "fold_limit_exceeded"`) in SARIF `runs[0].invocations[0].toolExecutionNotifications[]`.

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

## ⚡ Quick Start (Fork-Safe CI Setup)

Pin DevGuard by release tag or **full 40-character commit SHA** (`git rev-parse v1.3.0^{commit}`) in `.github/workflows/devguard.yml`, with `fetch-depth: 0` so commit history and base-branch `.devguard.json` verification are always available:

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
          fetch-depth: 0

      - name: Run DevGuard v1.3.0
        id: devguard
        uses: OkyWoww/DevGuard@v1.3.0 # Or pin by 40-char commit SHA (git rev-parse v1.3.0^{commit})
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
- **Total Cases:** `n = 129` (`TP = 48`, `TN = 63`, `EVASION = 18`, `knownMiss = 8`, `knownFP = 0`)
- **Cross-Rule TN Guarantee:** All `63/63` negative cases produce **0 false positives** across all rules (`DG001`–`DG008`, `DG004-DYN-01/02`, `DG005-EV-01`, `DG008-EV-01`).

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

#### Pass-O vs Pass-O+V Performance Benchmark Gate (`Test 70`, Median of 25 Iterations)
* **Full Corpus (`129` cases):** `Pass-O Only = 38.21 ms` vs `Pass-O+V = 40.43 ms` (**`+5.80%` overhead**, well under the `SPEC.md` §9 `<= +25%` gate; `0.313 ms/case`).
* **Non-Fold Baseline Subset (`108` cases with `editsApplied === 0`):** `Pass-O Only = 31.68 ms` vs `Pass-O+V = 31.46 ms` (**`-0.69%` overhead**, `3,191 cases/sec`).

#### Remaining Documented `knownMiss` Corpus Cases (`n = 8`, `0` in `v1.3.0` Scope)
Compared to `v1.2.1` (`14 knownMiss`), **`v1.3.0` resolved 6 documented evasion cases** (`DG004-EV-02` via `Pass-V`, `DG005-EV-01` via empty `.catch()` detector, `DG006-EV-01` via `FOLD-04`, `DG007-EV-01` & `DG007-EV-03` via `FOLD-01`/`02`, and `DG008-EV-01` via `do...while(true|1)`). The remaining `8` cases intentionally sit outside Stage 5 lexical/single-statement scope (inter-statement or inter-procedural aliasing):
- **`DG001-EV-03`** (`DG001`, `knownMiss`): Split string bracket lookup assigned to an intermediate alias (`const fn = (globalThis as ...)['ev' + 'al']; return fn(payload);`) — direct calls `globalThis["ev" + "al"](payload)` fold and detect via `Pass-V`, while aliased `fn(payload)` requires cross-statement data-flow tracking.
- **`DG004-EV-01`** (`DG004`, `knownMiss`): Dynamic `import(variable)` is now surfaced non-scoring by **`DG004-DYN-01`** while remaining an intentional `knownMiss` for scoring `DG004` slopsquatting.
- **`DG005-EV-02`** (`DG005`, `knownMiss`): `catch` delegates to a separate no-op helper (`ignore()`) instead of an empty block or `console.*`.
- **`DG005-EV-03`** (`DG005`, `knownMiss`): Dead variable assignment inside `catch` suppresses empty-catch check.
- **`DG006-EV-02`** (`DG006`, `knownMiss`): Aliased variable compare (`available >= amount`) before awaiting and mutating `account.balance`.
- **`DG006-EV-03`** (`DG006`, `knownMiss`): Check and `await`+mutation separated by more than 25 lines.
- **`DG008-EV-02`** (`DG008`, `knownMiss`): Aliased `fetch` reference (`const httpGet = fetch`) bypasses literal `fetch()` call matcher.
- **`DG008-EV-03`** (`DG008`, `knownMiss`): `while (running)` async loop where boolean guard is never mutated or broken.

#### External Real-World OSS Repository Validation (`SPEC.md` §9 & §10)
Validated offline (`DEVGUARD_TARGET=all`, `GEMINI_API_KEY=""`, zero temp artifacts left in repo) against shallow clones (`--depth 1`) of two production TypeScript repositories in `os.tmpdir()`:

| Repository | Commit SHA | In-Scope / Analyzed / Skipped | Wall-Clock Time | Findings Breakdown | SARIF v2.1.0 & v1.3.0 FP Audit |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **`sindresorhus/ky`** | `3541888` | `107` / `98` (`98 full`) / `0` | `661 ms` (`694 ms` CLI) | `DG004`: `21` (in `test-d/`), `DG005`: `3`, `DG008`: `285` (unbounded test/fetch calls); `fold_limit_exceeded`: `2` notes (`test/response-size.ts`, `test/retry.ts`) | SARIF valid (`519` results, `0` crashes); **`0` FP** across `DG004-DYN-01/02`, `DG005-EV-01`, `DG008-EV-01`, and `[via-fold]`; real `catch {}` confirmed at `source/core/Ky.ts:107` & `source/errors/NonError.ts:29` |
| **`colinhacks/zod`** | `e32e088` | `490` / `307` (`307 full`) / `1` (`should-build-site.sh`) | `1,423 ms` (`1,148 ms` CLI) | `DG001`: `1` (`packages/bench/memory/dict-mode.ts:13` `eval(...)`), `DG004-DYN-01`: `1` (`packages/bench/benchUtil.ts:5` dynamic `import(new URL(...).href)`), `DG005`: `31`, `DG008`: `1` | SARIF valid (`656` results, avg score `91/100`, `0` analysis failures); **`0` FP** across `DG004-DYN-01/02`, `DG005-EV-01`, `DG008-EV-01`, and `[via-fold]` |

See also [docs/benchmarks/realworld-2026-11-16.md](docs/benchmarks/realworld-2026-11-16.md) for the initial DevGuard `src/` self-scan baseline (`7` files under `src`, `0` false-positive findings across `DG001`–`DG008`).

### Known Limitations (Path Exclusions & CLI Scope)
* **Path Exclusions by Mode (`modified` vs. `all`):** Dot-prefixed paths (`.github/`, `.husky/`), `node_modules`, `dist`, `build`, `coverage`, `remotion`, `out`, `tests`, all files inside `scripts/`, anchored self-reference files (`src/devguardAnalyzer.ts`, `scripts/devguard_verify.py`, `devguard_verify.py` when `package.json` `"name": "devguard"`), `*.d.ts`, `*.test.*`, and `*.spec.*` are excluded from code auditing. In `modified` (`git diff`) mode, touched excluded paths enter the classifier as `ignored/excluded_path` and appear in PR Coverage as `- Ignored (excluded path): N` when `N > 0` so the coverage invariant covers 100% of `git diff`. In `all` mode, excluded directories are skipped during workspace traversal so `node_modules` is never walked.
* **Explicit CLI Arguments & `--version`:** Explicit file arguments passed on the CLI follow the coverage classifier (`.py` is analyzed with `partial` coverage; unsupported extensions like `.go` are marked `skipped`). Missing explicit CLI paths and invalid `fail_on_unanalyzable` values write `overall_score=N/A` and `audit_status=FAIL` to `GITHUB_OUTPUT` before exiting `1` rather than counting as `ignored/deleted`. Passing `--version` or `-v` prints the resolved package version (e.g. `1.3.0`) and exits `0`.

### Behavior Changes from `v1.2.1` to `v1.3.0`
* `.mjs`, `.cjs`, `.mts`, and `.cts` are discovered automatically in workspace and PR diff scans, `.py` files receive explicit `partial` coverage telemetry (`⚠️ PARTIALLY ANALYZED — language-agnostic rules only`), and `analyzed === 0` PRs output `overall_score=N/A` (with fail-closed `parse_error`/`internal_error` gate behavior).
* Added non-scoring dynamic module visibility (`DG004-DYN-01` / `DG004-DYN-02`), deterministic `Pass-V` constant folding (`FOLD-01`–`FOLD-04`) with `[via-fold]` provenance & `fold_limit_exceeded` SARIF notes, and anti-evasion detectors (`DG008-EV-01` & `DG005-EV-01`).

---

## 🧪 Local Development & Verification

DevGuard enforces a strict zero-dependency test harness using Node's built-in assertion & test runner (`node:test` compiled via `tsconfig.test.json` and executed in-process), currently verified at **75/75 passing tests** across [tests/corpus.test.ts](tests/corpus.test.ts) (`Corpus Benchmark`) and [tests/integration.test.ts](tests/integration.test.ts) (`Tests 1–74`):

```bash
# 1. Typecheck application, CLI, & tests
npm run lint

# 2. Build standalone web UI bundle
npm run build

# 3. Run zero-dependency benchmark + integration test suite (75/75 scenarios)
npm test

# 4. Print DevGuard CLI version cleanly under Node --experimental-strip-types
node --experimental-strip-types src/cli.ts --version

# 5. Regenerate labeled corpus Markdown summary
npm run corpus:report

# 6. Run DevGuard self-audit locally (zero-install Node 22 native TypeScript loader)
node --experimental-strip-types src/loader.mjs src/devguardAnalyzer.ts src/cli.ts src/githubCommenter.ts src/sarifGenerator.ts
```

---

## 📄 License

MIT License — Built for developers shipping fast with AI without sacrificing production security.
