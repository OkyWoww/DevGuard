# 🛡️ DevGuard v1.2.1 — The AI-Slop & Vibe-Coding Security Gatekeeper

[![Zero-Dependency Runtime](https://img.shields.io/badge/Runtime-100%25%20Zero--Dependency-emerald.svg)](#hybrid-dual-layer-architecture)
[![OASIS SARIF v2.1.0](https://img.shields.io/badge/SARIF-v2.1.0%20Compliant-blue.svg)](#quick-start-fork-safe-ci-setup)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-v1.2.1-black.svg)](#quick-start-fork-safe-ci-setup)
[![Tests 35/35 Passing](https://img.shields.io/badge/Tests-35%2F35%20Passing-success.svg)](#local-development--verification)

**DevGuard** is a deterministic CI/CD security gatekeeper engineered to catch silent failures, slopsquatting, leaked API keys, and financial race conditions hidden inside AI-generated (*Cursor, Windsurf, Copilot, Antigravity*) Pull Requests before they reach production.

Unlike generic LLM code reviewers that only leave probabilistic chat comments, DevGuard combines a **0-latency Deterministic Single-Pass Lexical & Heuristic Engine** with optional **Gemini Adversarial Reasoning**, posts **One-Click GitHub Suggested Changes** directly on offending diff lines, and uploads **OASIS SARIF v2.1.0** reports to GitHub Code Scanning.

---

## 🎯 Why DevGuard?

Modern AI coding assistants accelerate delivery, but frequently introduce subtle, high-impact defects ("AI-Slop") that pass traditional linters and unit tests:

* **Slopsquatting & Phantom Imports:** Hallucinated or typosquatted NPM packages (`lodahs`, `express-jwt-verify`) or subpaths absent from `package.json` that expose your build to supply-chain attacks.
* **Silent Failure Slop:** Empty `catch (e) {}` or `console.*`-only error handlers swallowing critical payment, authentication, or database failures.
* **Check-Then-Act Financial Race Conditions (TOCTOU):** Non-atomic balance, credit, or stock mutations separated by `await` calls without transactions or locks, enabling double-spending under concurrent load.
* **Hardcoded AI & Payment Keys:** Prototype API keys (`AIzaSy...`, `sk_live_...`, `ghp_...`, credentialed DB URIs, PEM keys, JWTs) accidentally committed into Pull Requests.
* **Unbounded Async Loops & Hanging Fetches:** `while (true)` / `for (;;)` polling loops without exit bounds or `fetch()` calls missing `AbortSignal.timeout()`, leading to worker exhaustion and runaway API bills.

---

## 📋 Deterministic Gatekeeper Rules (`DG001`–`DG008`)

Layer 1 runs **100% offline with zero third-party runtime dependencies** (`package.json` `"dependencies": {}`). Operating as a **Single-Pass Lexical & Heuristic Engine** (`analyzeLexicalStructure` + rule heuristics), it is deterministic and immune to LLM prompt-injection comments inside source code, with documented lexical evasion boundaries listed in the [Benchmark Corpus section](#benchmark-corpus--known-limitations-jsts--npm-scope).

| Rule ID | Category | Detection Target | SARIF Severity Rating | Default Severity | Inline Auto-Fix Suggestion |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **`DG001`** | Code Execution & Traversal | Arbitrary `eval()`, `new Function()`, unsanitized shell execution (`exec`), XSS sinks, and uncontained path traversal | `9.5` | `error` | Yes |
| **`DG002`** | Quality & Defense-in-Depth | Defense-in-depth hardening guidance explaining secondary deductions under zero-leniency audit | `5.0` | `warning` | — |
| **`DG003`** | Adversarial Audit / Gate Failure | Deep semantic or threshold gate failure when no standalone `DG001`/`inlineFindings` error was emitted | `8.0` | `error` | Yes |
| **`DG004`** | Supply Chain / Slopsquatting | Typosquatted NPM imports (Damerau-Levenshtein distance) & phantom dependencies / `#subpath` imports missing from `package.json` | `7.5` | `error` | Yes |
| **`DG005`** | Silent Failure Slop | Swallowed exceptions (empty or `console.*`-only `catch` blocks) escalated in auth/payment/DB flows | `7.0` | `error` / `warning` | Yes (`error`) |
| **`DG006`** | Financial Concurrency | Non-atomic balance/stock mutations (`check-then-act` TOCTOU across `await` boundaries without transactions/locks) | `8.5` | `error` | Yes (`db.$transaction`) |
| **`DG007`** | Credential & Secret Leak | Hardcoded provider keys, PEM private keys, credentialed URIs, JWTs & high-entropy secret literals | `9.0` | `error` | Yes (`process.env`) |
| **`DG008`** | Infrastructure Resilience | Unbounded async `while (true)` / `for (;;)` loops & external `fetch()` calls missing `AbortSignal.timeout()` / `AbortController` | `6.5` | `error` / `warning` | Yes (`AbortSignal.timeout` / bounded loop) |

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

### Exact Escalation Criteria for `DG005` & `DG008`
* **`DG005` (`warning` → `error`):**
  * **Default (`warning`):** Empty or `console.*`-only `catch` block in non-critical flows deducts `-10` `maintainability` (excluding cleanup calls like `unlink`/`rmSync`/`close` and `JSON.parse` fallbacks).
  * **Escalated (`error`):** When the `try` body matches a critical flow identifier (`payment`, `balance`, `wallet`, `ledger`, `transfer`, `charge`, `refund`, `deduct`, `invoice`, `auth`, `token`, `jwt`, `password`, `execute`, `query`, `transaction`, `writeFileSync`), `DG005` escalates to `error`, deducts `-20` `security` (`isCritical: true`) + `-15` `correctness`, provides an inline rethrow `suggestion`, and becomes non-suppressible inline.
* **`DG008` (`warning` → `error`):**
  * **Default (`warning`):** External `fetch()` calls lacking `signal`, `AbortSignal.timeout()`, or an enclosing `AbortController` (excluding local mock hosts `127.0.0.1`, `localhost`, `[::1]`) emit `warning` with `-10` `correctness`.
  * **Escalated (`error`):** Emits `error` whenever:
    1. An unbounded `while (true)`, `while (1)`, or `for (;;)` loop contains `await` without `break`, `return`, `throw`, `process.exit`, or a bounded retry check (`-25` `correctness`, `isCritical: true`), **or**
    2. A timeout-less `fetch()` targets a critical API/payment gateway (`openai`, `gemini`, `generativelanguage`, `anthropic`, `deepseek`, `radeon`, `stripe`, `payment`, `webhook`, `charge`, `verify`), deducting `-20` `security` (`isCritical: true`).

---

## 🔒 Non-Bypassable Suppression Policy & Base-Branch Allowlist

DevGuard supports controlled suppressions without letting AI-generated Pull Requests silently weaken critical security gates.

| Rule ID | Severity | Inline Suppression (`// devguard-ignore`) | `.devguard.json` Base-Branch Allowlist | Notes |
| :--- | :---: | :---: | :---: | :--- |
| **`DG001`** | `error` | ❌ Forbidden | ❌ Forbidden | Critical RCE/injection/traversal findings remain active with bypass warning |
| **`DG002`** | `warning` | ❌ Forbidden | ❌ Forbidden | Score/defense-in-depth notes are never suppressible |
| **`DG003`** | `error` | ❌ Forbidden | ❌ Forbidden | Score gate failures are never suppressible |
| **`DG004`** | `error` | ❌ Forbidden | ✅ Allowed (base branch only) | For monorepo/hoisted or vendored packages (base-branch `.devguard.json` only) |
| **`DG005`** | `warning` | ✅ Allowed (`>= 8` chars, 2+ words) | ❌ Forbidden | Only non-critical `warning` catches may be suppressed inline |
| **`DG005`** | `error` | ❌ Forbidden | ❌ Forbidden | Critical auth/payment/DB `error` catches cannot be suppressed |
| **`DG006`** | `error` | ❌ Forbidden | ✅ Allowed (base branch only) | External distributed locks can allowlist specific files on base branch |
| **`DG007`** | `error` | ❌ Forbidden | ❌ Forbidden | Hardcoded secret exposure cannot be suppressed |
| **`DG008`** | `warning` / `error` | ✅ Allowed (`>= 8` chars, 2+ words) | ❌ Forbidden | For upstream `AbortController` or framework-enforced deadlines |

### Lexer-Level Inline Suppressions
* Inline comments must be real `//` or `/* ... */` comments (not inside strings, template literals, or regex literals) immediately above or trailing the flagged line (permitted only for `DG008` and `DG005` `warning`):
  ```ts
  // devguard-ignore DG008: upstream AbortController enforces gateway deadline
  const response = await fetch('https://api.example.com/health');
  ```
* A meaningful justification reason of at least **8 characters** containing **at least two alphabetic words** (`/[A-Za-z]{2,}\s+[A-Za-z]{2,}/`) after `DGxxx:` is mandatory; dummy padding such as `"xxxxxxxx"` or `"........"` is rejected.
* Attempting inline suppression on forbidden rules (`DG001`, `DG004`, `DG005` `error`, `DG006`, `DG007`) leaves the finding active and appends `[Suppression ignored: DGxxx cannot be suppressed inline]`.

### Verified `.devguard.json` Allowlist Security Model
* **Strict Base-Branch Loading in CI:**
  * On Pull Requests (`GITHUB_BASE_REF`), DevGuard reads `.devguard.json` **strictly from git history** via `git show origin/${GITHUB_BASE_REF}:.devguard.json`.
  * On `push` events with a valid non-zero `before` SHA, DevGuard reads `${beforeSha}:.devguard.json`.
  * **PR edits to `.devguard.json` do NOT apply to the current PR**; they take effect **only after merge** into the base branch, and a warning banner is posted in the sticky PR comment whenever `.devguard.json` changed in the PR.
* **Validation Constraints:** Only `DG004` and `DG006` are permitted under `ignoreRulesByPath`, each entry requires a trimmed `reason` of length `>= 8` with at least two alphabetic words (`/[A-Za-z]{2,}\s+[A-Za-z]{2,}/`), and wildcard patterns (`*`, `**`, `**/...`, `../`, leading `/`, or non-directory globs) are rejected and reported in the sticky PR summary.
* **SARIF Audit Trail:** Active `inSource` and `external` suppressions are recorded on the PR summary table and emitted into `devguard-results.sarif` using standard OASIS `suppressions` metadata (`kind`, `justification`).

---

## 🔐 Layer 2 Pre-LLM Secret Redaction & Credential Rotation

Before transmitting any snippet to the Gemini REST endpoint (`generativelanguage.googleapis.com`), `prepareRedactedCodeForLlm` enforces a strict fail-closed privacy gate:

1. **Sensitive Filename Blocking (Case-Insensitive):** Immediately aborts Layer 2 (`Skipped: Redaction Abort`) without network calls for files matching:
   * `^\.env(\..+)?$` (e.g., `.env`, `.env.local`, `.ENV.PRODUCTION`) and `^\.(npmrc|netrc|pgpass)$`
   * `\.(pem|key|p12|pfx|crt|tfvars|tfstate|jks|keystore)$`
   * `^id_(rsa|ed25519|ecdsa)(\..+)?$` and `^kubeconfig(\..+)?$`
   * `(?:credentials|service-account).*\.json$`
2. **Layout-Preserving Secret Redaction (`redactSecretsPreservingLayout`):** Replaces PEM private key blocks, credentialed DB URI passwords, JWTs, `DG007` provider prefixes, and high-entropy secret string literals with `*` while preserving exact UTF-16 string length, `\n`, `\r`, and `\t` indices so line numbers stay aligned, and passes the Gemini API key in the `x-goog-api-key` request header instead of URL query strings.
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

Pin DevGuard by release tag or **full 40-character commit SHA** (`git rev-parse v1.2.1^{commit}`) in `.github/workflows/devguard.yml`, with `fetch-depth: 0` so commit history and base-branch `.devguard.json` verification are always available:

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

      - name: Run DevGuard v1.2.1
        id: devguard
        uses: OkyWoww/DevGuard@v1.2.1 # Or pin by 40-char commit SHA (git rev-parse v1.2.1^{commit})
        with:
          # Optional: Omit for 100% Free Offline Single-Pass Lexical & Heuristic mode
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
          min_score: '85'
          target_files: 'modified'

      - name: Upload DevGuard SARIF Report to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always() && (github.event_name != 'pull_request' || (github.event.pull_request.head.repo != null && github.event.pull_request.head.repo.full_name == github.repository))
        with:
          sarif_file: ${{ steps.devguard.outputs.sarif_file }}
```

### Action Inputs & Outputs ([action.yml](action.yml))

| Direction | Name | Default / Example | Description |
| :--- | :--- | :--- | :--- |
| **Input** | `gemini_api_key` | `""` | Optional Google Gemini API key for Layer 2 reasoning (falls back cleanly to Offline Single-Pass Lexical & Heuristic mode if omitted, forked, or rate-limited). |
| **Input** | `min_score` | `'85'` | Minimum Overall Guard score (`0`–`100`) required to pass CI (`DEVGUARD_MIN_SCORE`). |
| **Input** | `target_files` | `'modified'` | Audit scope: `'modified'` (git diff), `'all'` (workspace scan), or a specific file path (`DEVGUARD_TARGET`). |
| **Output** | `overall_score` | `96` | Aggregate Overall Guard score across audited files (`0`–`100`). |
| **Output** | `audit_status` | `PASS` / `FAIL` | Final gate verdict written to `GITHUB_OUTPUT`. |
| **Output** | `sarif_file` | `devguard-results.sarif` | Path to generated OASIS SARIF v2.1.0 report (`%SRCROOT%` POSIX URIs & GitHub Code Scanning `security-severity` rating (`5.0`–`9.5`)). |

---

## 🏗️ Hybrid Dual-Layer Architecture

1. **Layer 1 — Deterministic Single-Pass Lexical & Heuristic Engine (`0-Latency`, `Zero-Dependency`):**
   * Core analyzers ([src/devguardAnalyzer.ts](src/devguardAnalyzer.ts) and [src/rules/lexicalMasker.ts](src/rules/lexicalMasker.ts)) are browser-safe TypeScript modules; CLI & GitHub integration use only Node.js built-ins (`node:fs`, `node:path`, `node:child_process`, `node:module`) and native `fetch()`.
   * Immune to prompt-injection instructions embedded in comments (`// IGNORE ALL PREVIOUS INSTRUCTIONS`).
   * Cross-checks imported packages and `#subpath` aliases against ancestor `package.json` manifests and Node built-ins without external registry latency.
2. **Layer 2 — Gemini Adversarial Reasoning (`Fail-Closed Privacy` + `Fail-Open Resilience`):**
   * Uses a direct zero-dependency `fetch()` POST request to `generativelanguage.googleapis.com` with the `x-goog-api-key` header when running on same-repo workflows with a valid `AIzaSy...` key and after passing the Pre-LLM redaction & residual entropy gate.
   * Caps Layer 2 score deductions against clean Layer 1 verdicts so unverified LLM prose alone cannot fail a clean PR, and degrades fail-open to Layer 1 scores on timeout (`6.5s`), HTTP 4xx/5xx errors, or redaction aborts without breaking CI.
3. **One-Click PR Inline Remediation, Sticky Summary, & SARIF v2.1.0:**
   * Posts deduplicated inline review `suggestion` blocks per `path:line:ruleId` and maintains a single sticky PR summary table with Active Suppressions, Rejected Allowlist Entries, and explicit Layer 2 status badges (with `@mentions` and external markdown images neutralized).
   * Writes OASIS SARIF v2.1.0 logs with GitHub Code Scanning `security-severity` ratings (`5.0`–`9.5`), `%SRCROOT%` forward-slash relative URIs, and standard `suppressions` records without custom `partialFingerprints`.

---

## 📊 Benchmark Corpus & Known Limitations (JS/TS & NPM Scope)

DevGuard tracks detector precision, recall, and known evasion gaps transparently in [tests/corpus/cases.ts](tests/corpus/cases.ts) (`npm run corpus:report`). Because Layer 1 operates as a single-pass lexical and heuristic engine without full inter-procedural data-flow analysis, complex obfuscation or multi-hop aliasing remains out-of-scope for Layer 1 (`knownMiss` below). Current deterministic rules `DG004`–`DG008` target JS/TS & NPM ecosystems.

### Automated Corpus Report (`npm run corpus:report`)

- **Commit Short SHA:** `82c2622`
- **Date:** `2026-11-16`
- **Total Cases:** `n = 61` (`TP = 24`, `TN = 19`, `EVASION = 18`)

| Rule | TP (hit/total) | TN (FP/total) | EVASION (hit/total) | knownMiss | knownFP |
| :--- | :---: | :---: | :---: | :---: | :---: |
| DG001 | 4/4 | 0/3 | 2/3 | 1 | 0 |
| DG004 | 4/4 | 0/4 | 1/3 | 2 | 0 |
| DG005 | 4/4 | 0/3 | 0/3 | 3 | 0 |
| DG006 | 4/4 | 0/3 | 0/3 | 3 | 0 |
| DG007 | 4/4 | 0/3 | 1/3 | 2 | 0 |
| DG008 | 4/4 | 0/3 | 0/3 | 3 | 0 |

#### Documented `knownMiss` & `knownFP` Corpus Cases
- **`DG001-EV-03`** (`DG001`, `knownMiss`): Split string bracket lookup globalThis["ev" + "al"] obfuscation
- **`DG004-EV-01`** (`DG004`, `knownMiss`): Dynamic import(variable) hides slopsquatted specifier from static regex
- **`DG004-EV-02`** (`DG004`, `knownMiss`): Concatenated require() string bypasses literal import extraction
- **`DG005-EV-01`** (`DG005`, `knownMiss`): Promise .catch(() => {}) silently drops payment exception
- **`DG005-EV-02`** (`DG005`, `knownMiss`): Catch delegates to no-op helper instead of console/empty body
- **`DG005-EV-03`** (`DG005`, `knownMiss`): Dead variable assignment inside catch suppresses empty-catch check
- **`DG006-EV-01`** (`DG006`, `knownMiss`): Bracket property access wallet["balance"] for TOCTOU check and mutation
- **`DG006-EV-02`** (`DG006`, `knownMiss`): Aliased variable compare (available >= amount) before awaiting and mutating account.balance
- **`DG006-EV-03`** (`DG006`, `knownMiss`): Check and await+mutation separated by more than 25 lines
- **`DG007-EV-01`** (`DG007`, `knownMiss`): Split string concatenation inside source hides provider prefix across literals
- **`DG007-EV-03`** (`DG007`, `knownMiss`): Array join reconstruction avoids single contiguous secret literal
- **`DG008-EV-01`** (`DG008`, `knownMiss`): Unbounded do ... while (true) async loop
- **`DG008-EV-02`** (`DG008`, `knownMiss`): Aliased fetch reference (httpGet) bypasses literal fetch() call matcher
- **`DG008-EV-03`** (`DG008`, `knownMiss`): while (running) async loop where boolean guard is never mutated or broken

See [docs/benchmarks/realworld-2026-11-16.md](docs/benchmarks/realworld-2026-11-16.md) for the real-world self-scan baseline (`7` files under `src`, `0` false-positive findings across `DG001`–`DG008`).

---

## 🧪 Local Development & Verification

DevGuard enforces a strict zero-dependency test harness using Node's built-in test runner (`node:test`), currently verified at **35/35 passing tests** across [tests/corpus.test.ts](tests/corpus.test.ts) (`Corpus Benchmark`) and [tests/integration.test.ts](tests/integration.test.ts) (`Tests 1–34`):

```bash
# 1. Typecheck application, CLI, & tests
npm run lint

# 2. Build standalone web UI bundle
npm run build

# 3. Run zero-dependency benchmark + integration test suite (35/35 scenarios)
npm test

# 4. Regenerate labeled corpus Markdown summary
npm run corpus:report

# 5. Run DevGuard self-audit locally
npx tsx src/cli.ts src/devguardAnalyzer.ts src/cli.ts src/githubCommenter.ts src/sarifGenerator.ts
```

---

## 📄 License

MIT License — Built for developers shipping fast with AI without sacrificing production security.
