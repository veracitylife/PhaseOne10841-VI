#!/usr/bin/env tsx
/**
 * PhaseOne10841 Operator MCP — HTTP JSON-RPC server (read-mostly).
 * DEFENSIVE ONLY — binds to localhost by default.
 *
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { TOOL_DEFINITIONS, handleToolCall, type ToolCallContext } from './tools.js';

const HOST = process.env.PHASEONE_OPERATOR_MCP_HOST ?? '127.0.0.1';
const PORT = Number(process.env.PORT ?? process.env.PHASEONE_OPERATOR_MCP_PORT ?? 8090);
const GATEWAY_URL = process.env.GATEWAY_URL ?? 'http://127.0.0.1:8080';
const ADMIN_TOKEN = process.env.PHASEONE_OPERATOR_MCP_TOKEN;

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function rpcError(
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown
): JsonRpcResponse {
  return { jsonrpc: '2.0', id, error: { code, message, data } };
}

function rpcResult(id: string | number | null, result: unknown): JsonRpcResponse {
  return { jsonrpc: '2.0', id, result };
}

function toolContext(req: IncomingMessage): ToolCallContext {
  const adminHeader = req.headers['x-phaseone-admin-token'];
  const adminTokenHeader = Array.isArray(adminHeader) ? adminHeader[0] : adminHeader;
  const actorHeader = req.headers['x-phaseone-actor'];
  const actor = Array.isArray(actorHeader) ? actorHeader[0] : actorHeader;

  return {
    gatewayUrl: GATEWAY_URL,
    adminToken: ADMIN_TOKEN,
    adminTokenHeader,
    actor,
  };
}

async function handleRpc(req: IncomingMessage, res: ServerResponse, body: JsonRpcRequest): Promise<void> {
  const id = body.id ?? null;
  const method = body.method ?? '';

  if (body.jsonrpc && body.jsonrpc !== '2.0') {
    sendJson(res, 400, rpcError(id, -32600, 'Invalid Request: jsonrpc must be "2.0"'));
    return;
  }

  switch (method) {
    case 'initialize':
      sendJson(
        res,
        200,
        rpcResult(id, {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: {
            name: '@phaseone/operator-mcp',
            version: '0.1.1',
            product: 'PhaseOne10841',
            vendor: 'Veracity Integrity LLC',
          },
        })
      );
      return;

    case 'tools/list':
      sendJson(res, 200, rpcResult(id, { tools: TOOL_DEFINITIONS }));
      return;

    case 'tools/call': {
      const params = body.params ?? {};
      const name = typeof params.name === 'string' ? params.name : '';
      const args =
        params.arguments && typeof params.arguments === 'object' && !Array.isArray(params.arguments)
          ? (params.arguments as Record<string, unknown>)
          : {};

      if (!name) {
        sendJson(res, 400, rpcError(id, -32602, 'Invalid params: name required'));
        return;
      }

      const result = await handleToolCall(name, args, toolContext(req));
      sendJson(
        res,
        200,
        rpcResult(id, {
          content: result.content,
          isError: result.isError ?? false,
        })
      );
      return;
    }

    case 'ping':
      sendJson(res, 200, rpcResult(id, {}));
      return;

    default:
      sendJson(res, 404, rpcError(id, -32601, `Method not found: ${method}`));
  }
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method === 'GET' && (req.url === '/' || req.url === '/health')) {
    sendJson(res, 200, {
      ok: true,
      service: 'phaseone-operator-mcp',
      product: 'PhaseOne10841',
      version: '0.1.1',
      gateway: GATEWAY_URL,
      host: HOST,
      port: PORT,
    });
    return;
  }

  if (req.method !== 'POST') {
    sendJson(res, 405, { error: 'Method not allowed. Use POST for JSON-RPC.' });
    return;
  }

  let parsed: JsonRpcRequest;
  try {
    const raw = await readBody(req);
    parsed = JSON.parse(raw) as JsonRpcRequest;
  } catch {
    sendJson(res, 400, rpcError(null, -32700, 'Parse error'));
    return;
  }

  await handleRpc(req, res, parsed);
}

export function startServer(): ReturnType<typeof createServer> {
  const server = createServer((req, res) => {
    handleRequest(req, res).catch((err) => {
      console.error(
        JSON.stringify({
          ts: new Date().toISOString(),
          component: 'operator-mcp',
          event: 'request_error',
          message: err instanceof Error ? err.message : 'unknown',
        })
      );
      if (!res.headersSent) {
        sendJson(res, 500, rpcError(null, -32603, 'Internal error'));
      }
    });
  });

  server.listen(PORT, HOST, () => {
    console.log(
      JSON.stringify({
        ts: new Date().toISOString(),
        component: 'operator-mcp',
        event: 'listening',
        host: HOST,
        port: PORT,
        gateway: GATEWAY_URL,
      })
    );
  });

  return server;
}

const isMain =
  process.argv[1] &&
  (process.argv[1].endsWith('mcp-server/src/index.ts') ||
    process.argv[1].endsWith('phaseone-operator-mcp'));

if (isMain) {
  startServer();
}
