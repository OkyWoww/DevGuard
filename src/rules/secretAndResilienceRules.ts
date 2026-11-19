import {
  analyzeLexicalStructure,
  calculateShannonEntropy,
  type ExtractedStringLiteral,
  type InlineFinding,
  type LineFinding,
} from './lexicalMasker.ts';

export const DG007_PROVIDER_PATTERNS: ReadonlyArray<{
  label: string;
  envFallback: string;
  re: RegExp;
}> = [
  { label: 'Anthropic Claude API Key', envFallback: 'ANTHROPIC_API_KEY', re: /\bsk-ant-(?:api03-)?[A-Za-z0-9\-_]{20,}\b/ },
  { label: 'Google Gemini / GCP API Key', envFallback: 'GEMINI_API_KEY', re: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { label: 'Stripe Live Secret Key', envFallback: 'STRIPE_SECRET_KEY', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/ },
  { label: 'GitHub Personal / App Token', envFallback: 'GITHUB_TOKEN', re: /\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/ },
  { label: 'AWS Access Key ID', envFallback: 'AWS_ACCESS_KEY_ID', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: 'Slack Bot / Webhook Token', envFallback: 'SLACK_BOT_TOKEN', re: /\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b/ },
  { label: 'OpenAI / DeepSeek API Key', envFallback: 'OPENAI_API_KEY', re: /\bsk-(?:proj-|live-|None-)?[A-Za-z0-9_\-]{20,}\b/ },
];

const DG007_SENSITIVE_IDENT_RE =
  /(?:api_?key|api_?secret|secret_?key|private_?key|client_?secret|access_?token|auth_?token|jwt_?secret|webhook_?secret|signing_?secret|gemini_?(?:api_)?key|openai_?(?:api_)?key|anthropic_?(?:api_)?key|stripe_?(?:secret_)?key|aws_?secret(?:_access_key)?|password|passwd)$/i;

const DG007_DUMMY_RE =
  /(?:YOUR_|REPLACE_ME|PLACEHOLDER|CHANGEME|INSERT_|DUMMY|SAMPLE|EXAMPLE|TEST_KEY|MOCK_|FAKE_|^sk_test_|^pk_test_|^pk_live_|_HERE\b)/i;

const DG007_ROTATION_WARNING =
  'CRITICAL: Rotate/revoke this credential immediately. Replacing it in a new commit does not remove it from Git history.';

const PEM_PRIVATE_KEY_RE =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
const CREDENTIALED_DB_URI_RE =
  /(?:postgres(?:ql)?|mongodb(?:\+srv)?|redis|mysql):\/\/[^/\s:@]+:([^@\s]+)@/gi;
const JWT_TOKEN_RE =
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

function toUpperSnakeEnvName(identifier: string): string {
  const leaf = identifier.includes('.') ? identifier.split('.').pop()! : identifier;
  return leaf.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase();
}

function maskSecretPreview(secret: string): string {
  if (secret.length <= 4) return '*'.repeat(secret.length);
  return secret.slice(0, 4) + '*'.repeat(secret.length - 4);
}

function maskSpanPreservingLayout(chars: string[], start: number, end: number): void {
  const safeStart = Math.max(0, start);
  const safeEnd = Math.min(chars.length, end);
  for (let i = safeStart; i < safeEnd; i++) {
    const ch = chars[i];
    if (ch !== '\n' && ch !== '\r' && ch !== '\t') {
      chars[i] = '*';
    }
  }
}

interface EvaluatedSecretMatch {
  envVarName: string;
  detectionDetail: string;
  lineStartOffset: number;
  rawLine: string;
}

function evaluateSecretLiteral(
  rawCode: string,
  rawLines: string[],
  lit: ExtractedStringLiteral
): EvaluatedSecretMatch | null {
  if (lit.hasInterpolation) return null;

  const lineStartOffset = rawCode.lastIndexOf('\n', lit.startOffset - 1) + 1;
  const rawLine = rawLines[lit.line - 1] ?? '';

  if (/\bRegExp\s*\(/i.test(rawLine)) return null;
  const val = lit.value;
  if (val.length < 20 || val.startsWith('data:')) return null;

  const prefixBeforeLiteral = rawCode.slice(lineStartOffset, lit.startOffset);
  const assignMatch = prefixBeforeLiteral.match(
    /(?:^|[\s,{;(])(?:(?:export\s+)?(?:const|let|var)\s+|(?:public|private|readonly)\s+)?([A-Za-z_$][A-Za-z0-9_$.]*)\s*(?::\s*[^=]+)?[:=]\s*$/
  );
  const assignedIdent = assignMatch?.[1];
  const leafIdent = assignedIdent?.includes('.') ? assignedIdent.split('.').pop() : assignedIdent;

  let matchedProvider: { label: string; envFallback: string } | undefined;
  if (!DG007_DUMMY_RE.test(val)) {
    for (const pat of DG007_PROVIDER_PATTERNS) {
      if (pat.re.test(val)) {
        matchedProvider = { label: pat.label, envFallback: pat.envFallback };
        break;
      }
    }
  }

  const readsEnv = /\b(?:process\.env\.|import\.meta\.env\.|Deno\.env\.get\s*\()/i.test(rawLine);

  if (matchedProvider) {
    return {
      envVarName: assignedIdent ? toUpperSnakeEnvName(assignedIdent) : matchedProvider.envFallback,
      detectionDetail: `Hardcoded ${matchedProvider.label} (${maskSecretPreview(val)}) terdeteksi pada baris ${lit.line}.`,
      lineStartOffset,
      rawLine,
    };
  }

  if (
    !readsEnv &&
    val.length <= 256 &&
    !/\s/.test(val) &&
    !/^(?:https?|wss?):\/\//i.test(val) &&
    !/^(?:\.{0,2}\/)/.test(val) &&
    !DG007_DUMMY_RE.test(val) &&
    !/^(.)\1{5,}$/.test(val) &&
    !/^(?:x+|0+|12345|abcde)/i.test(val) &&
    leafIdent &&
    DG007_SENSITIVE_IDENT_RE.test(leafIdent)
  ) {
    const entropy = calculateShannonEntropy(val);
    if (entropy >= 3.8) {
      return {
        envVarName: toUpperSnakeEnvName(leafIdent),
        detectionDetail: `Kredensial ber-entropi tinggi (${maskSecretPreview(val)}, ${entropy.toFixed(2)} bits/char) ditugaskan ke '${leafIdent}' secara hardcoded pada baris ${lit.line}.`,
        lineStartOffset,
        rawLine,
      };
    }
  }

  return null;
}

function maskKnownTokensOnly(input: string): string {
  const chars = input.split('');
  for (const pat of DG007_PROVIDER_PATTERNS) {
    const globalRe = new RegExp(pat.re.source, 'g');
    for (const m of input.matchAll(globalRe)) {
      if (m.index !== undefined) maskSpanPreservingLayout(chars, m.index, m.index + m[0].length);
    }
  }
  return chars.join('');
}

/**
 * Redacts hardcoded provider secrets, high-entropy credentials, PEM private keys,
 * credentialed database URIs, and JWTs with `*` while preserving exact UTF-16 `.length`
 * and keeping every `\n`, `\r`, and `\t` at its exact index.
 */
export function redactSecretsPreservingLayout(code: string): string {
  if (typeof code !== 'string') {
    throw new TypeError('redactSecretsPreservingLayout requires a string');
  }
  const chars = code.split('');

  try {
    // 1. PEM private key blocks
    for (const m of code.matchAll(PEM_PRIVATE_KEY_RE)) {
      if (m.index !== undefined) {
        maskSpanPreservingLayout(chars, m.index, m.index + m[0].length);
      }
    }

    // 2. Credentialed DB URI passwords (group 1 between ':' and '@')
    for (const m of code.matchAll(CREDENTIALED_DB_URI_RE)) {
      if (m.index !== undefined && m[1]) {
        const passEnd = m.index + m[0].length - 1; // index of '@'
        const passStart = passEnd - m[1].length;
        maskSpanPreservingLayout(chars, passStart, passEnd);
      }
    }

    // 3. JSON Web Tokens (JWT)
    for (const m of code.matchAll(JWT_TOKEN_RE)) {
      if (m.index !== undefined) {
        maskSpanPreservingLayout(chars, m.index, m.index + m[0].length);
      }
    }

    // 4. Known DG007 provider prefixes anywhere in text (except RegExp(...) scanner definitions)
    const lines = code.split('\n');
    for (const pat of DG007_PROVIDER_PATTERNS) {
      const globalRe = new RegExp(pat.re.source, 'g');
      for (const m of code.matchAll(globalRe)) {
        if (m.index === undefined) continue;
        const lineIdx = code.slice(0, m.index).split('\n').length - 1;
        const lineText = lines[lineIdx] ?? '';
        if (/\bRegExp\s*\(/.test(lineText) || /\/[^\n/]*\\b/.test(lineText)) continue;
        maskSpanPreservingLayout(chars, m.index, m.index + m[0].length);
      }
    }

    // 5. Specific high-entropy secret string literals (only the matched secret literal value)
    const lexical = analyzeLexicalStructure(code, false);
    for (const lit of lexical.stringLiterals) {
      if (evaluateSecretLiteral(code, lines, lit) && lit.endOffset > lit.startOffset + 2) {
        maskSpanPreservingLayout(chars, lit.startOffset + 1, lit.endOffset - 1);
      }
    }
  } catch {
    return chars.join('');
  }

  return chars.join('');
}

const COMMON_FILE_EXT_RE =
  /\.(?:ts|tsx|js|jsx|mjs|cjs|json|md|png|jpe?g|svg|gif|webp|css|scss|html|py|yml|yaml|sarif|txt|lock)$/i;

function countCharClasses(token: string): number {
  let classes = 0;
  if (/[A-Z]/.test(token)) classes++;
  if (/[a-z]/.test(token)) classes++;
  if (/[0-9]/.test(token)) classes++;
  if (/[+/_=-]/.test(token)) classes++;
  return classes;
}

/**
 * Independent fail-closed residual secret scanner that must NOT reuse `DG007_PROVIDER_PATTERNS`.
 * Returns masked location descriptors only (`residual-high-entropy-token@line:N`), never raw tokens.
 */
export function findResidualSecretLikeTokens(code: string): string[] {
  if (typeof code !== 'string') {
    throw new TypeError('findResidualSecretLikeTokens requires a string');
  }

  const residuals: string[] = [];
  const seen = new Set<string>();
  const addResidual = (kind: string, line: number): void => {
    const descriptor = `${kind}@line:${line}`;
    if (!seen.has(descriptor)) {
      seen.add(descriptor);
      residuals.push(descriptor);
    }
  };

  // Strip comments (keeping newlines intact) without masking string literals
  const commentStripped = code
    .replace(/\/\*[\s\S]*?\*\//g, (block) => block.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:\\])\/\/[^\n]*/g, (_full, prefix: string) => `${prefix}`);

  const lines = commentStripped.split('\n');
  const candidateTokenRe = /[A-Za-z0-9+/_=-]{24,256}/g;
  const residualPemRe = /-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY-----/i;
  const residualUriCredRe = /:\/\/[^/\s:@]+:[^@\s*]+@/;

  for (let idx = 0; idx < lines.length; idx++) {
    const lineNum = idx + 1;
    const lineText = lines[idx];

    if (residualPemRe.test(lineText)) {
      addResidual('residual-pem-header', lineNum);
    }
    if (residualUriCredRe.test(lineText)) {
      addResidual('residual-uri-credential', lineNum);
    }

    for (const m of lineText.matchAll(candidateTokenRe)) {
      if (m.index === undefined) continue;
      const tok = m[0];
      const before = lineText.slice(Math.max(0, m.index - 24), m.index);

      // Exclude HTTP URLs, data:* base64 URIs, and source/asset file paths
      if (/(?:https?:\/\/[^\s]*|data:[^\s]*base64,)$/i.test(before) || /^https?/i.test(tok)) continue;
      if (tok.includes('/') && COMMON_FILE_EXT_RE.test(tok)) continue;
      if (countCharClasses(tok) < 3) continue;

      const entropy = calculateShannonEntropy(tok);
      if (entropy >= 4.2) {
        addResidual('residual-high-entropy-token', lineNum);
      }
    }
  }

  return residuals;
}

const SENSITIVE_BASENAME_PATTERNS: ReadonlyArray<RegExp> = [
  /^\.env(\..+)?$/i,
  /^\.(npmrc|netrc|pgpass)$/i,
  /^kubeconfig(\..+)?$/i,
  /\.(pem|key|p12|pfx|crt|tfvars|tfstate|jks|keystore)$/i,
  /^id_(rsa|ed25519|ecdsa)(\..+)?$/i,
  /(?:credentials|service-account).*\.json$/i,
];

export interface PrepareLlmOptions {
  redactFn?: (source: string) => string;
}

/**
 * Fail-closed Pre-LLM verification gate. Blocks sensitive filenames, redacts secrets,
 * verifies zero surviving DG007 or residual high-entropy tokens, and aborts on any error.
 */
export function prepareRedactedCodeForLlm(
  filePath: string,
  code: string,
  options?: PrepareLlmOptions
): { safeCode: string; aborted: boolean; reason?: string } {
  const normalizedPath = typeof filePath === 'string' ? filePath.replace(/\\/g, '/') : '';
  const baseName = normalizedPath.split('/').pop() || '';

  if (SENSITIVE_BASENAME_PATTERNS.some((re) => re.test(baseName))) {
    return { safeCode: '', aborted: true, reason: 'Sensitive filename blocked' };
  }

  try {
    if (typeof code !== 'string') {
      throw new TypeError('Source code for LLM must be a string');
    }

    const redact = options?.redactFn ?? redactSecretsPreservingLayout;
    const redacted = redact(code);
    if (typeof redacted !== 'string') {
      throw new TypeError('Redactor did not return a string');
    }

    const redactedLines = redacted.split('\n');
    const lexical = analyzeLexicalStructure(redacted, false);
    const verifyFindings: LineFinding[] = [];
    const verifyInline: InlineFinding[] = [];

    detectHardcodedSecrets(redacted, redactedLines, lexical.stringLiterals, verifyFindings, verifyInline);
    const residuals = findResidualSecretLikeTokens(redacted);

    if (verifyFindings.length > 0 || verifyInline.length > 0 || residuals.length > 0) {
      return { safeCode: '', aborted: true, reason: 'Residual secret check triggered fail-closed abort' };
    }

    return { safeCode: redacted, aborted: false };
  } catch {
    return { safeCode: '', aborted: true, reason: 'Residual secret check triggered fail-closed abort' };
  }
}

/** DG007: Detects hardcoded provider-prefixed secrets and high-entropy credential assignments. */
export function detectHardcodedSecrets(
  rawCode: string,
  rawLines: string[],
  stringLiterals: ExtractedStringLiteral[],
  findings: LineFinding[],
  inlineFindings: InlineFinding[]
): Set<number> {
  if (typeof rawCode !== 'string' || !Array.isArray(stringLiterals)) {
    throw new TypeError('detectHardcodedSecrets expects string code and extracted literals');
  }
  const flaggedLines = new Set<number>();

  try {
    for (const lit of stringLiterals) {
      if (flaggedLines.has(lit.line)) continue;
      const evaluated = evaluateSecretLiteral(rawCode, rawLines, lit);
      if (!evaluated) continue;

      flaggedLines.add(lit.line);
      const { envVarName, detectionDetail, lineStartOffset, rawLine } = evaluated;
      const colStart = lit.startOffset - lineStartOffset;
      const colEnd = lit.endLine === lit.line ? lit.endOffset - lineStartOffset : rawLine.length;
      const suggestion =
        maskKnownTokensOnly(rawLine.slice(0, colStart)) +
        `process.env.${envVarName} ?? ''` +
        maskKnownTokensOnly(rawLine.slice(colEnd));

      const msg = `${detectionDetail} Pindahkan secret ke environment variable (process.env.${envVarName}). ${DG007_ROTATION_WARNING}`;
      findings.push({
        line: lit.line,
        category: 'security',
        penalty: 40,
        shortReason: `-40 [DG007] Hardcoded API/cloud secret pada baris ${lit.line}`,
        detailedReason: msg,
        isCritical: true,
      });
      inlineFindings.push({
        ruleId: 'DG007',
        line: lit.line,
        severity: 'error',
        message: msg,
        suggestion,
      });
    }
  } catch {
    return flaggedLines;
  }

  return flaggedLines;
}

function findMatchingDelim(maskedCode: string, openIdx: number, openChar: string, closeChar: string): number {
  let depth = 1;
  for (let i = openIdx + 1; i < maskedCode.length; i++) {
    if (maskedCode[i] === openChar) depth++;
    else if (maskedCode[i] === closeChar && --depth === 0) return i;
  }
  return -1;
}

function findEnclosingBlockRange(maskedCode: string, pos: number): { start: number; end: number } {
  let depth = 0;
  let start = -1;
  for (let i = pos - 1; i >= 0; i--) {
    if (maskedCode[i] === '}') depth++;
    else if (maskedCode[i] === '{') {
      if (depth === 0) {
        start = i;
        break;
      }
      depth--;
    }
  }
  if (start >= 0) {
    const closeIdx = findMatchingDelim(maskedCode, start, '{', '}');
    if (closeIdx > start) return { start, end: closeIdx };
  }
  return { start: Math.max(0, pos - 600), end: Math.min(maskedCode.length, pos + 600) };
}

const UNBOUNDED_LOOP_BOUNDED_EXIT_RE =
  /\b(?:break|return|throw|process\.exit)\b|\b(?:maxRetries|maxAttempts|MAX_ATTEMPTS|attempts?|retries)(?:\+\+|--)?\s*(?:<|<=|>|>=|===|!==)/i;

const BOUNDED_LOOP_EXIT_RE =
  /\b(?:return|throw|process\.exit)\b|\b(?:maxRetries|maxAttempts|MAX_ATTEMPTS|attempts?|retries)(?:\+\+|--)?\s*(?:<|<=|>|>=|===|!==)/i;

function blankBraceInterior(chars: string[], openBraceIdx: number): number {
  const closeIdx = findMatchingDelim(chars.join(''), openBraceIdx, '{', '}');
  if (closeIdx === -1) return openBraceIdx;
  for (let i = openBraceIdx + 1; i < closeIdx; i++) {
    if (chars[i] !== '\n') chars[i] = ' ';
  }
  return closeIdx;
}

function stripNestedFunctionBodies(maskedBody: string): string {
  const chars = maskedBody.split('');
  const fnOrArrowRe = /\bfunction\b(?:\s+[A-Za-z_$][\w$]*)?\s*\(|=>\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = fnOrArrowRe.exec(maskedBody)) !== null) {
    if (m[0].endsWith('{')) {
      blankBraceInterior(chars, m.index + m[0].length - 1);
      continue;
    }
    const openParenIdx = m.index + m[0].length - 1;
    const closeParenIdx = findMatchingDelim(maskedBody, openParenIdx, '(', ')');
    if (closeParenIdx === -1) continue;
    let i = closeParenIdx + 1;
    while (i < maskedBody.length && maskedBody[i] !== '{' && maskedBody[i] !== ';') {
      i++;
    }
    if (i < maskedBody.length && maskedBody[i] === '{') {
      blankBraceInterior(chars, i);
    }
  }
  return chars.join('');
}

function stripNestedControlBodies(outerFnScope: string): string {
  const chars = outerFnScope.split('');
  const innerControlRe = /\b(?:for|while|switch)\s*\(|\bdo\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = innerControlRe.exec(outerFnScope)) !== null) {
    if (m[0].endsWith('{')) {
      blankBraceInterior(chars, m.index + m[0].length - 1);
      continue;
    }
    const openParenIdx = m.index + m[0].length - 1;
    const closeParenIdx = findMatchingDelim(outerFnScope, openParenIdx, '(', ')');
    if (closeParenIdx === -1) continue;
    let i = closeParenIdx + 1;
    while (i < outerFnScope.length && /\s/.test(outerFnScope[i])) i++;
    if (outerFnScope[i] === '{') {
      blankBraceInterior(chars, i);
    }
  }
  return chars.join('');
}

function hasOuterLabeledBreak(outerFnScope: string): boolean {
  const innerLabels = new Set<string>();
  const labelDefRe = /(?:^|[;{}])\s*([A-Za-z_$][\w$]*)\s*:/gm;
  let lm: RegExpExecArray | null;
  while ((lm = labelDefRe.exec(outerFnScope)) !== null) {
    if (lm[1] !== 'case' && lm[1] !== 'default') {
      innerLabels.add(lm[1]);
    }
  }
  const labeledBreakRe = /\bbreak\s+([A-Za-z_$][\w$]*)\b/g;
  let bm: RegExpExecArray | null;
  while ((bm = labeledBreakRe.exec(outerFnScope)) !== null) {
    if (!innerLabels.has(bm[1])) return true;
  }
  return false;
}

/** Shared scope-aware body-scan helper for DG008 (`while`/`for`) and DG008-EV-01 (`do...while`). */
function isUnboundedAsyncLoopBody(maskedBody: string): boolean {
  if (!/\bawait\b/.test(maskedBody)) return false;
  // Preserve fast path when outer body has neither exit keywords nor retry counters at all
  if (!UNBOUNDED_LOOP_BOUNDED_EXIT_RE.test(maskedBody)) return true;

  const outerFnScope = stripNestedFunctionBodies(maskedBody);
  if (BOUNDED_LOOP_EXIT_RE.test(outerFnScope)) return false;

  const outerLoopScope = stripNestedControlBodies(outerFnScope);
  if (/\bbreak\b/.test(outerLoopScope)) return false;
  if (hasOuterLabeledBreak(outerFnScope)) return false;

  return true;
}

/** DG008: Detects unbounded async loops and external fetch() calls lacking AbortSignal timeouts. */
export function detectMissingTimeoutsAndLoops(
  rawCode: string,
  maskedCode: string,
  rawLines: string[],
  findings: LineFinding[],
  inlineFindings: InlineFinding[]
): void {
  if (typeof rawCode !== 'string' || typeof maskedCode !== 'string') {
    throw new TypeError('detectMissingTimeoutsAndLoops requires string sources');
  }
  const flaggedLines = new Set<number>();

  const loopRe = /\b(?:while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;\s*;\s*\))\s*\{/g;

  let loopMatch: RegExpExecArray | null;
  while ((loopMatch = loopRe.exec(maskedCode)) !== null) {
    const openBraceIdx = loopMatch.index + loopMatch[0].length - 1;
    const closeBraceIdx = findMatchingDelim(maskedCode, openBraceIdx, '{', '}');
    if (closeBraceIdx === -1) continue;

    const maskedBody = maskedCode.slice(openBraceIdx + 1, closeBraceIdx);
    if (!isUnboundedAsyncLoopBody(maskedBody)) continue;

    const startLine = maskedCode.slice(0, loopMatch.index).split('\n').length;
    const endLine = maskedCode.slice(0, closeBraceIdx).split('\n').length;
    flaggedLines.add(startLine);

    const rawLine = rawLines[startLine - 1] ?? '';
    const lineStart = rawCode.lastIndexOf('\n', loopMatch.index - 1) + 1;
    const localMatchOffset = loopMatch.index - lineStart;
    const loopHeaderEnd = loopMatch[0].lastIndexOf('{');
    const suggestion =
      localMatchOffset >= 0 && localMatchOffset + loopHeaderEnd <= rawLine.length
        ? rawLine.slice(0, localMatchOffset) +
          'for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) ' +
          rawLine.slice(localMatchOffset + loopHeaderEnd)
        : 'for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {';

    const msg = `Unbounded async loop tanpa kondisi keluar eksplisit pada baris ${startLine} berisiko menggantungkan worker dan membengkakkan kuota API.`;
    findings.push({
      line: startLine,
      category: 'correctness',
      penalty: 25,
      shortReason: `-25 [DG008] Unbounded async loop tanpa break/return/batas iterasi (baris ${startLine})`,
      detailedReason: msg,
      isCritical: true,
    });
    inlineFindings.push({
      ruleId: 'DG008',
      line: startLine,
      endLine: endLine > startLine ? endLine : undefined,
      severity: 'error',
      message: msg,
      suggestion,
    });
  }

  // DG008-EV-01: Unbounded async do { ... } while (true | 1) loops (SPEC §6.2)
  const doLoopRe = /\bdo\s*\{/g;
  let doMatch: RegExpExecArray | null;
  while ((doMatch = doLoopRe.exec(maskedCode)) !== null) {
    let prevIdx = doMatch.index - 1;
    while (prevIdx >= 0 && /\s/.test(maskedCode[prevIdx])) prevIdx--;
    if (prevIdx >= 0 && (maskedCode[prevIdx] === '.' || maskedCode[prevIdx] === ':')) continue;

    const openBraceIdx = doMatch.index + doMatch[0].length - 1;
    const closeBraceIdx = findMatchingDelim(maskedCode, openBraceIdx, '{', '}');
    if (closeBraceIdx === -1) continue;

    const afterClose = maskedCode.slice(closeBraceIdx + 1);
    const whileClauseMatch = afterClose.match(/^\s*while\s*\(\s*(?:true|1)\s*\)/);
    if (!whileClauseMatch) continue;

    const afterWhileIdx = closeBraceIdx + 1 + whileClauseMatch[0].length;
    if (/^\s*\{/.test(maskedCode.slice(afterWhileIdx))) continue;

    const maskedBody = maskedCode.slice(openBraceIdx + 1, closeBraceIdx);
    if (!isUnboundedAsyncLoopBody(maskedBody)) continue;

    const startLine = maskedCode.slice(0, doMatch.index).split('\n').length;
    const endLine = maskedCode.slice(0, afterWhileIdx).split('\n').length;
    if (flaggedLines.has(startLine)) continue;
    flaggedLines.add(startLine);

    const msg = `[DG008-EV-01] Unbounded async do-while loop tanpa kondisi keluar eksplisit pada baris ${startLine} berisiko menggantungkan worker dan membengkakkan kuota API.`;
    findings.push({
      line: startLine,
      category: 'correctness',
      penalty: 10,
      shortReason: `-10 [DG008] [DG008-EV-01] Unbounded async do-while loop tanpa break/return/batas iterasi (baris ${startLine})`,
      detailedReason: msg,
    });
    inlineFindings.push({
      ruleId: 'DG008',
      line: startLine,
      endLine: endLine > startLine ? endLine : undefined,
      severity: 'warning',
      message: msg,
      suggestion: 'for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {',
    });
  }

  const fetchRe = /(?:^|[^.\w$]|\b(?:globalThis|window)\.)fetch\s*\(/g;
  const criticalGatewayRe =
    /(?:openai|gemini|generativelanguage|anthropic|deepseek|radeon|stripe|payment|webhook|charge|verify)/i;
  const localMockHostRe = /(?:127\.0\.0\.1|localhost|\[::1\])/i;

  let fetchMatch: RegExpExecArray | null;
  while ((fetchMatch = fetchRe.exec(maskedCode)) !== null) {
    const openParenIdx = maskedCode.indexOf('(', fetchMatch.index);
    if (openParenIdx === -1) continue;
    const closeParenIdx = findMatchingDelim(maskedCode, openParenIdx, '(', ')');
    if (closeParenIdx === -1) continue;

    const fetchKeywordIdx = maskedCode.indexOf('fetch', fetchMatch.index);
    const fetchLine = maskedCode.slice(0, fetchKeywordIdx).split('\n').length;
    const fetchEndLine = maskedCode.slice(0, closeParenIdx).split('\n').length;
    if (flaggedLines.has(fetchLine)) continue;

    const maskedArgs = maskedCode.slice(openParenIdx + 1, closeParenIdx);
    const rawArgs = rawCode.slice(openParenIdx + 1, closeParenIdx);

    if (/\bsignal\b|\bAbortSignal\.timeout\b|\bAbortController\b/.test(maskedArgs)) continue;
    if (localMockHostRe.test(rawArgs)) continue;

    const enclosing = findEnclosingBlockRange(maskedCode, fetchKeywordIdx);
    if (/\bnew\s+AbortController\b|\bAbortSignal\.timeout\b/.test(maskedCode.slice(enclosing.start, enclosing.end))) {
      continue;
    }

    const isCriticalGateway =
      criticalGatewayRe.test(rawArgs) || criticalGatewayRe.test(rawCode.slice(enclosing.start, enclosing.end));
    flaggedLines.add(fetchLine);

    const rawLine = rawLines[fetchLine - 1] ?? '';
    let suggestion = 'fetch(url, { signal: AbortSignal.timeout(15_000) })';
    if (fetchEndLine === fetchLine && !maskedArgs.includes(',')) {
      const lineStart = rawCode.lastIndexOf('\n', fetchKeywordIdx - 1) + 1;
      const localClose = closeParenIdx - lineStart;
      if (localClose > 0 && localClose <= rawLine.length) {
        suggestion =
          rawLine.slice(0, localClose) +
          ', { signal: AbortSignal.timeout(15_000) }' +
          rawLine.slice(localClose);
      }
    }

    if (isCriticalGateway) {
      const msg = `Pemanggilan fetch() ke gateway kritis pada baris ${fetchLine} tidak menyertakan signal AbortSignal.timeout() sehingga worker dapat macet permanen.`;
      findings.push({
        line: fetchLine,
        category: 'security',
        penalty: 20,
        shortReason: `-20 [DG008] fetch() gateway kritis tanpa AbortSignal.timeout() (baris ${fetchLine})`,
        detailedReason: msg,
        isCritical: true,
      });
      inlineFindings.push({
        ruleId: 'DG008',
        line: fetchLine,
        endLine: fetchEndLine > fetchLine ? fetchEndLine : undefined,
        severity: 'error',
        message: msg,
        suggestion,
      });
    } else {
      const msg = `Pemanggilan fetch() pada baris ${fetchLine} tidak menyertakan signal AbortSignal.timeout() sebagai batas waktu jaringan.`;
      findings.push({
        line: fetchLine,
        category: 'correctness',
        penalty: 10,
        shortReason: `-10 [DG008] fetch() tanpa signal AbortSignal.timeout() (baris ${fetchLine})`,
        detailedReason: msg,
      });
      inlineFindings.push({
        ruleId: 'DG008',
        line: fetchLine,
        endLine: fetchEndLine > fetchLine ? fetchEndLine : undefined,
        severity: 'warning',
        message: msg,
        suggestion,
      });
    }
  }
}

