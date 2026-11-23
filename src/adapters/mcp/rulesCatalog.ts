export interface RuleExplanation {
  ruleId: string;
  name: string;
  defaultSeverity: 'error' | 'warning' | 'note';
  securitySeverity: string;
  cwe: string[];
  shortDescription: string;
  fullDescription: string;
  remediation: string;
  truePositiveExample: string;
  trueNegativeExample: string;
}

const RULES_CATALOG: ReadonlyArray<RuleExplanation> = [
  {
    ruleId: 'DG001',
    name: 'AdversarialSecurityOrLogicFlaw',
    defaultSeverity: 'error',
    securitySeverity: '9.5',
    cwe: ['CWE-94', 'CWE-78', 'CWE-89', 'CWE-693'],
    shortDescription: 'Critical security vulnerability or exploitable logic flaw detected by DevGuard.',
    fullDescription:
      'Detects dangerous dynamic code or command execution sinks, SQL injection string interpolation, path traversal, and critical logic bypasses.',
    remediation:
      'Avoid dynamic code evaluation and shell string interpolation. Use parameterized queries, safe argument arrays, and strict input validation.',
    truePositiveExample: 'export function run(expr: string) { return eval(expr); }',
    trueNegativeExample: 'export function parseConfig(raw: string) { return JSON.parse(raw); }',
  },
  {
    ruleId: 'DG001-ALIAS-01',
    name: 'AliasedDynamicExecutionSink',
    defaultSeverity: 'warning',
    securitySeverity: '5.5',
    cwe: ['CWE-94', 'CWE-78'],
    shortDescription: 'Non-scoring warning: invocation of an intra-procedural alias pointing to a dangerous execution sink.',
    fullDescription:
      'Non-scoring informational warning emitted when a local alias (up to depth 2) bound to eval, Function, or child_process.exec/execSync is invoked. Does not penalize repository scores.',
    remediation:
      'Avoid aliasing or invoking dynamic code evaluation (eval, Function) and shell execution sinks (child_process.exec/execSync). Use safe structured APIs or argument arrays without shell interpolation.',
    truePositiveExample: 'const run = eval; run(userInput);',
    trueNegativeExample: 'const exec = /pattern/.exec; exec(input);',
  },
  {
    ruleId: 'DG002',
    name: 'DefenseInDepthRecommendation',
    defaultSeverity: 'warning',
    securitySeverity: '5.0',
    cwe: ['CWE-693'],
    shortDescription: 'Defense-in-Depth architectural hardening recommendation.',
    fullDescription:
      'Zero-Leniency audit note explaining secondary architectural hardening opportunities such as rate limiting, strict schema validation, or audit logging.',
    remediation:
      'Apply defense-in-depth controls appropriate for production workloads (structured logging, rate limits, strict boundary checks).',
    truePositiveExample: 'Endpoint validates input but lacks rate-limiting or structured audit trail.',
    trueNegativeExample: 'Endpoint enforces schema validation, parameterized queries, and audit logging.',
  },
  {
    ruleId: 'DG003',
    name: 'OverallScoreBelowThreshold',
    defaultSeverity: 'error',
    securitySeverity: '8.0',
    cwe: ['CWE-693'],
    shortDescription: 'File overall DevGuard score fell below minimum configured threshold.',
    fullDescription:
      'Emitted when the combined Security, Correctness, and Maintainability score is below the configured min_score threshold without a more specific blocking finding.',
    remediation:
      'Resolve the reported security, correctness, and maintainability deductions until the file meets or exceeds the minimum score threshold.',
    truePositiveExample: 'File scores 70/100 when min_score is set to 85/100.',
    trueNegativeExample: 'File scores 95/100 when min_score is set to 85/100.',
  },
  {
    ruleId: 'DG004',
    name: 'HallucinatedOrTyposquattedPackage',
    defaultSeverity: 'error',
    securitySeverity: '7.5',
    cwe: ['CWE-829'],
    shortDescription: 'Hallucinated, undeclared, or typosquatted package dependency detected.',
    fullDescription:
      'Detects bare package imports absent from declared package.json/workspace manifests or with suspicious edit distance to popular npm packages (slopsquatting).',
    remediation:
      'Verify the exact package name, install and declare it in package.json, or remove hallucinated imports.',
    truePositiveExample: "import _ from 'lodahs';",
    trueNegativeExample: "import * as path from 'node:path';",
  },
  {
    ruleId: 'DG004-DYN-01',
    name: 'UnanalyzableDynamicImportSpecifier',
    defaultSeverity: 'warning',
    securitySeverity: '3.5',
    cwe: ['CWE-829'],
    shortDescription: 'Non-scoring warning: dynamic import() specifier prevents static supply-chain verification.',
    fullDescription:
      'Non-scoring informational warning emitted when dynamic import() uses a non-literal specifier that cannot be statically checked against package.json or typosquatting targets.',
    remediation:
      'Use static string literal specifiers or map user input through a fixed allowlist of static import thunks.',
    truePositiveExample: 'export async function loadPlugin(name: string) { return import(name); }',
    trueNegativeExample: "export async function loadPlugin() { return import('./plugins/default.js'); }",
  },
  {
    ruleId: 'DG004-DYN-02',
    name: 'UnanalyzableDynamicRequireSpecifier',
    defaultSeverity: 'warning',
    securitySeverity: '3.5',
    cwe: ['CWE-829'],
    shortDescription: 'Non-scoring warning: dynamic require() specifier prevents static supply-chain verification.',
    fullDescription:
      'Non-scoring informational warning emitted when CommonJS require() uses a non-literal specifier that cannot be statically checked against package.json.',
    remediation:
      'Replace dynamic require(variable) with static imports or an explicit allowlist switch statement.',
    truePositiveExample: 'export function loadMod(name: string) { return require(name); }',
    trueNegativeExample: "export function loadFs() { return require('node:fs'); }",
  },
  {
    ruleId: 'DG004-WS-NEW',
    name: 'NewWorkspacePackageInPullRequest',
    defaultSeverity: 'warning',
    securitySeverity: '3.5',
    cwe: ['CWE-829'],
    shortDescription: 'Non-scoring notice: new workspace package added in pull request.',
    fullDescription:
      'Informational notice emitted when a pull request introduces a new workspace package not present on the base branch, preventing silent slopsquatting bypasses.',
    remediation:
      'Review the newly added workspace package name and manifest to confirm it is intentional.',
    truePositiveExample: 'PR adds packages/lodahs/package.json and imports "lodahs".',
    trueNegativeExample: 'Workspace package already exists on base branch.',
  },
  {
    ruleId: 'DG004-WS-UNPARSED',
    name: 'UnparseableWorkspaceConfiguration',
    defaultSeverity: 'warning',
    securitySeverity: '3.5',
    cwe: ['CWE-829'],
    shortDescription: 'Non-scoring notice: workspace configuration could not be parsed (fail-closed per source).',
    fullDescription:
      'Emitted when package.json, pnpm-workspace.yaml, or tsconfig.json fails strict parsing, exceeds size limits, or uses unsupported constructs. The failed source contributes zero package names.',
    remediation:
      'Fix syntax errors or unsupported YAML constructs (anchors, flow collections, tabs) in the workspace configuration file.',
    truePositiveExample: 'pnpm-workspace.yaml containing YAML anchors (&a) or flow syntax ([packages/*]).',
    trueNegativeExample: 'Standard pnpm-workspace.yaml with a block list under packages:.',
  },
  {
    ruleId: 'DG004-WS-SHALLOW',
    name: 'ShallowCloneBaseRefUnavailable',
    defaultSeverity: 'warning',
    securitySeverity: '3.5',
    cwe: ['CWE-829'],
    shortDescription: 'Non-scoring notice: shallow clone prevented reading base-branch workspace configuration.',
    fullDescription:
      'Informational notice emitted when CI runs with fetch-depth: 1 and origin/<baseRef> cannot be fetched, causing workspace resolution to fail closed to 0 admitted base packages.',
    remediation:
      'Configure actions/checkout@v4 with fetch-depth: 0 so DevGuard can verify base-branch workspace manifests and .devguard.json.',
    truePositiveExample: 'actions/checkout@v4 using default fetch-depth: 1 in a monorepo pull request.',
    trueNegativeExample: 'actions/checkout@v4 configured with fetch-depth: 0.',
  },
  {
    ruleId: 'DG005',
    name: 'SwallowedExceptionInFlow',
    defaultSeverity: 'warning',
    securitySeverity: '7.0',
    cwe: ['CWE-390'],
    shortDescription: 'Empty or console-only catch block swallows runtime failures.',
    fullDescription:
      'Detects catch blocks or .catch() handlers that ignore exceptions or only log to console without rethrowing, returning a failure state, or performing safe recovery.',
    remediation:
      'Rethrow the error, return a typed error result, or handle failure explicitly with compensating state rollback.',
    truePositiveExample:
      'Empty or log-only catch block wrapping a critical payment/auth call without rethrow or rollback.',
    trueNegativeExample:
      'try { await chargeCard(order); } catch (err) { logger.error(err); throw err; }',
  },
  {
    ruleId: 'DG006',
    name: 'NonAtomicBalanceOrStockMutation',
    defaultSeverity: 'error',
    securitySeverity: '8.5',
    cwe: ['CWE-362'],
    shortDescription: 'Non-atomic check-then-act mutation across await boundary (TOCTOU race condition).',
    fullDescription:
      'Detects code that checks balance, stock, credits, or quota before an await boundary and mutates it afterward without an atomic database transaction or lock.',
    remediation:
      'Wrap check-and-mutate operations in an atomic database transaction ($transaction / FOR UPDATE / conditional WHERE balance >= amount update).',
    truePositiveExample:
      'if (user.balance >= amount) { await logAudit(user.id); user.balance -= amount; }',
    trueNegativeExample:
      'await db.$transaction(async (tx) => { await tx.account.updateMany({ where: { id, balance: { gte: amount } }, data: { balance: { decrement: amount } } }); });',
  },
  {
    ruleId: 'DG007',
    name: 'HardcodedSecretOrApiKey',
    defaultSeverity: 'error',
    securitySeverity: '9.0',
    cwe: ['CWE-798'],
    shortDescription: 'Hardcoded AI, payment, or cloud API secret detected in source code.',
    fullDescription:
      'Detects provider-prefixed API keys (OpenAI, Stripe, GitHub, Google, AWS, Slack) and high-entropy credential literals assigned directly in source code.',
    remediation:
      'Load secrets exclusively from environment variables or a secret manager, and rotate any exposed credentials immediately.',
    truePositiveExample: 'Assigning a raw provider API key literal directly in source (e.g. const apiKey = "<provider-key-literal>").',
    trueNegativeExample: 'const apiKey = process.env.OPENAI_API_KEY;',
  },
  {
    ruleId: 'DG008',
    name: 'MissingTimeoutOrUnboundedAsyncLoop',
    defaultSeverity: 'error',
    securitySeverity: '6.5',
    cwe: ['CWE-400'],
    shortDescription: 'Missing network AbortSignal timeout or unbounded async polling loop.',
    fullDescription:
      'Detects external fetch() calls without AbortSignal.timeout() / AbortController and unbounded while(true) async loops lacking termination bounds.',
    remediation:
      'Pass signal: AbortSignal.timeout(10000) to fetch() calls and enforce explicit max-iteration limits on async polling loops.',
    truePositiveExample: 'export async function getData(url: string) { return fetch(url); }',
    trueNegativeExample:
      'export async function getData(url: string) { return fetch(url, { signal: AbortSignal.timeout(5000) }); }',
  },
];

const RULES_BY_ID = new Map<string, RuleExplanation>(
  RULES_CATALOG.map((rule) => [rule.ruleId.toUpperCase(), rule])
);

export function listSupportedRuleIds(): string[] {
  return RULES_CATALOG.map((r) => r.ruleId);
}

export function explainDevGuardRule(
  ruleId: string
): { found: true; rule: RuleExplanation } | { found: false; supportedRuleIds: string[] } {
  if (typeof ruleId !== 'string') {
    return { found: false, supportedRuleIds: listSupportedRuleIds() };
  }
  const normalized = ruleId.trim().toUpperCase();
  const match = RULES_BY_ID.get(normalized);
  if (!match) {
    return { found: false, supportedRuleIds: listSupportedRuleIds() };
  }
  return { found: true, rule: match };
}
