export type CliFormat = 'text' | 'json' | 'sarif';

export interface CliCheckOptions {
  kind: 'check';
  paths: string[];
  staged: boolean;
  changedSince: string | null;
  format: CliFormat;
  minScore: number;
  configPath: string | null;
  outputPath: string | null;
}

export type ParsedCliCommand =
  | { kind: 'help' }
  | { kind: 'version' }
  | { kind: 'install-hook' }
  | { kind: 'error'; message: string }
  | CliCheckOptions;

const VALID_FORMATS = new Set<string>(['text', 'json', 'sarif']);

export function getCliUsageText(): string {
  return [
    'Usage:',
    '  devguard check [paths...] [options]',
    '  devguard install-hook',
    '  devguard --version | -v',
    '  devguard --help | -h',
    '',
    'Options for `devguard check`:',
    '  --staged                 Scan only Git staged files',
    '  --changed-since <ref>    Scan files changed since a Git ref (e.g. origin/main)',
    '  --format <text|json|sarif>  Output format (default: text)',
    '  --min-score <0-100>      Minimum Overall Guard score to pass (default: 85)',
    '  --config <path>          Path to .devguard.json config file',
    '  --output, -o <path>      Write report output to a file instead of stdout',
    '  -h, --help               Show this help message',
    '  -v, --version            Print DevGuard version',
    '',
    'Exit Codes:',
    '  0  Audit passed (no blocking findings and score >= min-score)',
    '  1  Audit failed (blocking findings or score below min-score)',
    '  2  Operational or argument error (invalid flags, bad config, or Git error)',
  ].join('\n');
}

function splitOptionToken(token: string): { flag: string; inlineValue: string | null } {
  const eqIdx = token.indexOf('=');
  if (eqIdx === -1) {
    return { flag: token, inlineValue: null };
  }
  return {
    flag: token.slice(0, eqIdx),
    inlineValue: token.slice(eqIdx + 1),
  };
}

/**
 * Zero-dependency CLI argument parser for `devguard`.
 * Returns a strongly-typed command union; never calls process.exit().
 */
export function parseCliArgs(argv: readonly string[]): ParsedCliCommand {
  if (!Array.isArray(argv)) {
    return { kind: 'error', message: 'Invalid argv input: expected an array of strings.' };
  }

  if (argv.length === 0) {
    return { kind: 'help' };
  }

  const first = argv[0];
  if (first === '--help' || first === '-h') {
    return { kind: 'help' };
  }
  if (first === '--version' || first === '-v') {
    return { kind: 'version' };
  }

  if (first === 'install-hook') {
    if (argv.length > 1) {
      const extra = argv[1];
      if (extra === '--help' || extra === '-h') {
        return { kind: 'help' };
      }
      return { kind: 'error', message: `Unknown option for install-hook: ${extra}` };
    }
    return { kind: 'install-hook' };
  }

  if (first !== 'check') {
    if (first.startsWith('-')) {
      return { kind: 'error', message: `Unknown option: ${first}` };
    }
    return { kind: 'error', message: `Unknown command: ${first}. Expected "check" or "install-hook".` };
  }

  const paths: string[] = [];
  let staged = false;
  let changedSince: string | null = null;
  let format: CliFormat = 'text';
  let minScore = 85;
  let configPath: string | null = null;
  let outputPath: string | null = null;
  let positionalOnly = false;

  for (let i = 1; i < argv.length; i++) {
    const rawToken = argv[i];
    if (typeof rawToken !== 'string') {
      return { kind: 'error', message: 'Invalid non-string CLI argument.' };
    }

    if (positionalOnly) {
      paths.push(rawToken);
      continue;
    }

    if (rawToken === '--') {
      positionalOnly = true;
      continue;
    }

    if (rawToken === '--help' || rawToken === '-h') {
      return { kind: 'help' };
    }
    if (rawToken === '--version' || rawToken === '-v') {
      return { kind: 'version' };
    }

    if (!rawToken.startsWith('-')) {
      paths.push(rawToken);
      continue;
    }

    const { flag, inlineValue } = splitOptionToken(rawToken);

    const consumeValue = (): { ok: true; value: string } | { ok: false; error: string } => {
      if (inlineValue !== null) {
        if (inlineValue.length === 0) {
          return { ok: false, error: `Option ${flag} requires a non-empty value.` };
        }
        return { ok: true, value: inlineValue };
      }
      const next = argv[i + 1];
      if (next === undefined || next.length === 0) {
        return { ok: false, error: `Option ${flag} requires a value.` };
      }
      i++;
      return { ok: true, value: next };
    };

    switch (flag) {
      case '--staged': {
        if (inlineValue !== null) {
          return { kind: 'error', message: 'Option --staged does not accept a value.' };
        }
        staged = true;
        break;
      }
      case '--changed-since': {
        const res = consumeValue();
        if (!res.ok) return { kind: 'error', message: res.error };
        if (res.value.startsWith('-')) {
          return {
            kind: 'error',
            message: `Invalid Git ref for --changed-since: "${res.value}" (refs cannot start with "-")`,
          };
        }
        changedSince = res.value;
        break;
      }
      case '--format': {
        const res = consumeValue();
        if (!res.ok) return { kind: 'error', message: res.error };
        if (!VALID_FORMATS.has(res.value)) {
          return {
            kind: 'error',
            message: `Invalid --format "${res.value}". Expected one of: text, json, sarif.`,
          };
        }
        format = res.value as CliFormat;
        break;
      }
      case '--min-score': {
        const res = consumeValue();
        if (!res.ok) return { kind: 'error', message: res.error };
        if (!/^\d+$/.test(res.value)) {
          return {
            kind: 'error',
            message: `Invalid --min-score "${res.value}". Expected an integer between 0 and 100.`,
          };
        }
        const parsed = Number.parseInt(res.value, 10);
        if (!Number.isFinite(parsed) || parsed < 0 || parsed > 100) {
          return {
            kind: 'error',
            message: `Invalid --min-score "${res.value}". Expected an integer between 0 and 100.`,
          };
        }
        minScore = parsed;
        break;
      }
      case '--config': {
        const res = consumeValue();
        if (!res.ok) return { kind: 'error', message: res.error };
        configPath = res.value;
        break;
      }
      case '--output':
      case '-o': {
        const res = consumeValue();
        if (!res.ok) return { kind: 'error', message: res.error };
        outputPath = res.value;
        break;
      }
      default:
        return { kind: 'error', message: `Unknown option: ${flag}` };
    }
  }

  if (staged && changedSince !== null) {
    return {
      kind: 'error',
      message: 'Options --staged and --changed-since cannot be used together.',
    };
  }

  return {
    kind: 'check',
    paths,
    staged,
    changedSince,
    format,
    minScore,
    configPath,
    outputPath,
  };
}
