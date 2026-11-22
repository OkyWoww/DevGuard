import * as path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { getDevGuardVersion } from '../../core/types.ts';
import { MCP_LIMITS } from './security.ts';
import {
  handleMcpCheckFiles,
  handleMcpCheckSnippet,
  handleMcpExplainRule,
} from './tools.ts';

/**
 * Official Model Context Protocol versions supported by DevGuard MCP server.
 * Negotiated strictly during `initialize`; unknown versions are rejected with -32602.
 */
export const SUPPORTED_MCP_PROTOCOL_VERSIONS = [
  '2025-11-25',
  '2025-06-18',
  '2025-03-26',
  '2024-11-05',
] as const;

const SUPPORTED_VERSION_SET = new Set<string>(SUPPORTED_MCP_PROTOCOL_VERSIONS);

const JSONRPC_PARSE_ERROR = -32700;
const JSONRPC_INVALID_REQUEST = -32600;
const JSONRPC_METHOD_NOT_FOUND = -32601;
const JSONRPC_INVALID_PARAMS = -32602;
const JSONRPC_INTERNAL_ERROR = -32603;

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: {
    readOnlyHint: true;
    destructiveHint: false;
    idempotentHint: true;
    openWorldHint: false;
  };
}

export const MCP_TOOL_DEFINITIONS: ReadonlyArray<McpToolDefinition> = [
  {
    name: 'devguard_check_files',
    description:
      'Run deterministic, offline DevGuard security and reliability audit on workspace-relative files (read-only, path-jailed to workspace root).',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['paths'],
      properties: {
        paths: {
          type: 'array',
          items: { type: 'string' },
          minItems: 1,
          maxItems: MCP_LIMITS.maxFilesPerCall,
          description: 'Workspace-relative file paths to audit.',
        },
        min_score: {
          type: 'integer',
          minimum: 0,
          maximum: 100,
          description: 'Optional minimum passing score threshold (default: 85).',
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'devguard_check_snippet',
    description:
      'Run deterministic, offline DevGuard audit on an in-memory code snippet without touching disk.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['language', 'code'],
      properties: {
        language: {
          type: 'string',
          description: 'Language identifier (e.g. ts, tsx, js, jsx, py).',
        },
        code: {
          type: 'string',
          description: `Source code snippet to audit (max ${MCP_LIMITS.maxSnippetBytes} bytes).`,
        },
        virtual_path: {
          type: 'string',
          description: 'Optional virtual file path hint (e.g. src/wallet.ts).',
        },
        min_score: {
          type: 'integer',
          minimum: 0,
          maximum: 100,
          description: 'Optional minimum passing score threshold (default: 85).',
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'devguard_explain_rule',
    description:
      'Explain a DevGuard rule ID with severity, CWE references, remediation guidance, and TP/TN examples.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['rule_id'],
      properties: {
        rule_id: {
          type: 'string',
          description: 'DevGuard rule identifier (e.g. DG001, DG004, DG006, DG007).',
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
];

function makeError(
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown
): JsonRpcResponse {
  return {
    jsonrpc: '2.0',
    id,
    error: data === undefined ? { code, message } : { code, message, data },
  };
}

function makeResult(id: string | number | null, result: unknown): JsonRpcResponse {
  return {
    jsonrpc: '2.0',
    id,
    result,
  };
}

export interface McpSession {
  handleRawLine(rawLine: string): JsonRpcResponse | null;
}

/**
 * Creates a stateful JSON-RPC 2.0 MCP session bound to a single workspace root.
 * Pure message handler: zero stdout writes, zero network, zero shell calls.
 */
export function createMcpSession(workspaceRoot: string): McpSession {
  const resolvedRoot = path.resolve(workspaceRoot);
  let initialized = false;

  const dispatchToolCall = (
    id: string | number | null,
    params: unknown
  ): JsonRpcResponse => {
    if (!params || typeof params !== 'object' || Array.isArray(params)) {
      return makeError(id, JSONRPC_INVALID_PARAMS, 'tools/call requires an object params payload.');
    }
    const p = params as { name?: unknown; arguments?: unknown };
    if (typeof p.name !== 'string' || p.name.trim().length === 0) {
      return makeError(id, JSONRPC_INVALID_PARAMS, 'tools/call requires a non-empty string "name".');
    }
    const toolArgs =
      p.arguments === undefined
        ? {}
        : p.arguments && typeof p.arguments === 'object' && !Array.isArray(p.arguments)
          ? (p.arguments as Record<string, unknown>)
          : null;

    if (toolArgs === null) {
      return makeError(id, JSONRPC_INVALID_PARAMS, 'tools/call "arguments" must be a JSON object.');
    }

    let execResult: { isError?: boolean; payload: Record<string, unknown> };
    try {
      switch (p.name) {
        case 'devguard_check_files':
          execResult = handleMcpCheckFiles(resolvedRoot, toolArgs);
          break;
        case 'devguard_check_snippet':
          execResult = handleMcpCheckSnippet(toolArgs);
          break;
        case 'devguard_explain_rule':
          execResult = handleMcpExplainRule(toolArgs);
          break;
        default:
          return makeError(id, JSONRPC_INVALID_PARAMS, `Unknown tool: "${p.name}".`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return makeError(id, JSONRPC_INTERNAL_ERROR, `Internal tool execution error: ${msg}`);
    }

    return makeResult(id, {
      content: [
        {
          type: 'text',
          text: JSON.stringify(execResult.payload),
        },
      ],
      ...(execResult.isError ? { isError: true } : {}),
    });
  };

  return {
    handleRawLine(rawLine: string): JsonRpcResponse | null {
      const trimmed = rawLine.trim();
      if (trimmed.length === 0) return null;

      if (Buffer.byteLength(trimmed, 'utf-8') > MCP_LIMITS.maxIncomingMessageBytes) {
        return makeError(
          null,
          JSONRPC_INVALID_REQUEST,
          `Incoming JSON-RPC message exceeds ${MCP_LIMITS.maxIncomingMessageBytes} bytes limit.`
        );
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        return makeError(null, JSONRPC_PARSE_ERROR, 'Parse error: invalid JSON.');
      }

      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return makeError(null, JSONRPC_INVALID_REQUEST, 'Invalid Request: expected JSON object.');
      }

      const req = parsed as Partial<JsonRpcRequest>;
      const hasId = Object.prototype.hasOwnProperty.call(req, 'id');
      const id: string | number | null =
        typeof req.id === 'string' || typeof req.id === 'number' || req.id === null
          ? req.id
          : null;

      if (req.jsonrpc !== '2.0' || typeof req.method !== 'string' || req.method.length === 0) {
        return makeError(id, JSONRPC_INVALID_REQUEST, 'Invalid Request: missing jsonrpc "2.0" or method.');
      }

      // Notifications (no id) must never elicit a JSON-RPC response.
      // Note: notifications/initialized does NOT bypass the `initialize` handshake.
      if (!hasId) {
        return null;
      }

      switch (req.method) {
        case 'initialize': {
          const p =
            req.params && typeof req.params === 'object' && !Array.isArray(req.params)
              ? (req.params as { protocolVersion?: unknown })
              : {};
          const requestedVersion = p.protocolVersion;
          if (typeof requestedVersion !== 'string' || !SUPPORTED_VERSION_SET.has(requestedVersion)) {
            return makeError(
              id,
              JSONRPC_INVALID_PARAMS,
              `Unsupported MCP protocolVersion "${String(requestedVersion)}". Supported versions: ${SUPPORTED_MCP_PROTOCOL_VERSIONS.join(', ')}.`,
              { supportedVersions: [...SUPPORTED_MCP_PROTOCOL_VERSIONS] }
            );
          }
          initialized = true;
          return makeResult(id, {
            protocolVersion: requestedVersion,
            capabilities: {
              tools: { listChanged: false },
            },
            serverInfo: {
              name: 'devguard-mcp',
              version: getDevGuardVersion(),
            },
          });
        }

        case 'ping':
          return makeResult(id, {});

        case 'tools/list':
          if (!initialized) {
            return makeError(
              id,
              JSONRPC_INVALID_REQUEST,
              'Server not initialized. Send "initialize" request first.'
            );
          }
          return makeResult(id, { tools: MCP_TOOL_DEFINITIONS });

        case 'tools/call':
          if (!initialized) {
            return makeError(
              id,
              JSONRPC_INVALID_REQUEST,
              'Server not initialized. Send "initialize" request first.'
            );
          }
          return dispatchToolCall(id, req.params);

        default:
          return makeError(id, JSONRPC_METHOD_NOT_FOUND, `Method not found: "${req.method}".`);
      }
    },
  };
}

export interface McpStdioOptions {
  workspaceRoot?: string;
  input?: NodeJS.ReadableStream;
  output?: { write: (chunk: string) => unknown };
  stderr?: { write: (chunk: string) => unknown };
}

/**
 * Starts the zero-dependency newline-delimited JSON-RPC 2.0 MCP server over stdio.
 * Strictly writes ONLY valid JSON-RPC 2.0 lines to `output` (stdout);
 * all diagnostic messages go exclusively to `stderr`.
 */
export function startMcpStdioServer(options?: McpStdioOptions): void {
  const workspaceRoot = path.resolve(options?.workspaceRoot ?? process.cwd());
  const input = options?.input ?? process.stdin;
  const output = options?.output ?? process.stdout;
  const stderr = options?.stderr ?? process.stderr;

  const session = createMcpSession(workspaceRoot);
  const decoder = new StringDecoder('utf8');
  let buffer = '';
  let discardingOversizedLine = false;

  const emitResponse = (res: JsonRpcResponse | null): void => {
    if (res === null) return;
    output.write(`${JSON.stringify(res)}\n`);
  };

  input.on('data', (chunk: string | Buffer) => {
    const text = typeof chunk === 'string' ? chunk : decoder.write(chunk);
    let offset = 0;

    while (offset < text.length) {
      if (discardingOversizedLine) {
        const nl = text.indexOf('\n', offset);
        if (nl === -1) {
          return;
        }
        discardingOversizedLine = false;
        offset = nl + 1;
        continue;
      }

      const nl = text.indexOf('\n', offset);
      if (nl === -1) {
        buffer += text.slice(offset);
        if (Buffer.byteLength(buffer, 'utf8') > MCP_LIMITS.maxIncomingMessageBytes) {
          buffer = '';
          discardingOversizedLine = true;
          emitResponse(
            makeError(
              null,
              JSONRPC_INVALID_REQUEST,
              `Incoming JSON-RPC message exceeds ${MCP_LIMITS.maxIncomingMessageBytes} bytes limit.`
            )
          );
        }
        return;
      }

      const line = buffer + text.slice(offset, nl);
      buffer = '';
      offset = nl + 1;
      emitResponse(session.handleRawLine(line));
    }
  });

  input.on('end', () => {
    const trailing = decoder.end();
    if (!discardingOversizedLine) {
      const finalLine = buffer + trailing;
      if (finalLine.trim().length > 0) {
        emitResponse(session.handleRawLine(finalLine));
      }
    }
    buffer = '';
    discardingOversizedLine = false;
  });

  input.on('error', (err: Error) => {
    stderr.write(`[devguard-mcp] stdin error: ${err.message}\n`);
  });
}
