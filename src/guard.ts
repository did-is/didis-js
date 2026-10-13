/**
 * Fail-closed pre-execution guard for agent tools.
 *
 * Before a wrapped tool handler runs, the guard checks:
 *  1. Definition pin (local, no network): the tool definition the agent actually received
 *     hashes to the SHA-256 you approved (same RFC 8785 JCS hash DID.is reports as
 *     `definitionSha256`). Catches MCP "rug-pull" drift, including servers DID.is cannot reach.
 *  2. Delegation (DID.is `verify-tool`): the configured agent DID holds a registered, VALID
 *     delegation whose leaf capabilities grant the tool. ALLOW is cached briefly; DENY and
 *     errors are never cached.
 *
 * Any failure (drift, DENY, network error, 429, malformed answer) throws `DidisGuardError`
 * and the handler is not called. `attestMcpPins` is an optional, separate startup check that
 * asks DID.is to fetch a public MCP server and compares its hashes with your pins; do not call
 * it per tool call (it makes an outbound request and is rate limited).
 */
import type { DidisClient, McpInspection, ToolAuthorization } from "./index.js";

export type DidisGuardErrorCode =
  | "TOOL_DRIFT"
  | "TOOL_DEFINITION_MISSING"
  | "TOOL_NOT_AUTHORIZED"
  | "GUARD_UNAVAILABLE"
  | "GUARD_MISCONFIGURED";

export class DidisGuardError extends Error {
  readonly code: DidisGuardErrorCode;
  readonly tool: string;
  readonly detail?: Record<string, unknown>;

  constructor(code: DidisGuardErrorCode, tool: string, message: string, detail?: Record<string, unknown>) {
    super(`${code}: ${message}`);
    this.name = "DidisGuardError";
    this.code = code;
    this.tool = tool;
    this.detail = detail;
  }
}

/** RFC 8785 (JCS) canonical JSON, matching the DID.is server's `rfc8785-binary64-v1` profile. */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("JCS: non-finite numbers are not JSON");
      return Object.is(value, -0) ? "0" : String(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(",")}]`;
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort(); // UTF-16 code unit order
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
    }
    default:
      throw new TypeError(`JCS: unsupported value of type ${typeof value}`);
  }
}

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** SHA-256 of a tool definition exactly as an MCP server returned it in `tools/list`. */
export function toolDefinitionSha256(definition: unknown): Promise<string> {
  return sha256Hex(canonicalJson(definition));
}

function byteCompare(a: string, b: string): number {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

/** Inventory hash of a `tools/list` result, identical to DID.is `inventoryHash`. */
export async function mcpInventoryHash(tools: { name?: unknown }[]): Promise<string> {
  const pairs = await Promise.all(tools.map(async (t) => [typeof t.name === "string" ? t.name : "", await toolDefinitionSha256(t)] as [string, string]));
  pairs.sort((a, b) => byteCompare(a[0], b[0]));
  return sha256Hex(canonicalJson(pairs));
}

/** Builds `{ toolName: definitionSha256 }` pins from a `tools/list` result you have reviewed. */
export async function pinToolDefinitions(tools: { name?: unknown }[]): Promise<Record<string, string>> {
  const pins: Record<string, string> = {};
  for (const t of tools) {
    if (typeof t.name !== "string" || !t.name) throw new TypeError("every tool needs a string name");
    if (t.name in pins) throw new TypeError(`duplicate tool name '${t.name}'`);
    pins[t.name] = await toolDefinitionSha256(t);
  }
  return pins;
}

type Definition = unknown | (() => unknown | Promise<unknown>);

export interface DidisGuardOptions {
  client: DidisClient;
  /** The agent DID from your runtime configuration. Never take it from model output. */
  agent: string;
  /** Require the delegation chain to start at this root DID. Strongly recommended. */
  root?: string;
  /** Approved `{ toolName: definitionSha256 }`. A pinned tool must be given its definition. */
  pins?: Record<string, string>;
  /** Refuse tools that have no pin. Default `false`. */
  requirePins?: boolean;
  /** How long an ALLOW is reused (ms). Default 30 s; 0 disables. Capped by the delegation expiry. */
  allowCacheMs?: number;
  /** Called after every decision (for audit logs). Must not throw. */
  onDecision?: (event: { tool: string; allowed: boolean; code?: DidisGuardErrorCode; reason: string; cached: boolean }) => void;
}

export interface GuardCallOptions {
  /** The tool name as granted by capabilities, e.g. `github:create_issue`. */
  tool: string;
  /** The definition the agent received, or a function returning the current one. */
  definition?: Definition;
}

export interface DidisGuard {
  /** Throws `DidisGuardError` unless the call may proceed. */
  check(call: GuardCallOptions): Promise<void>;
  /** Wraps a handler so it only runs after `check` passes. */
  wrap<A extends unknown[], R>(call: GuardCallOptions, handler: (...args: A) => R | Promise<R>): (...args: A) => Promise<Awaited<R>>;
  /** Drops cached ALLOW decisions (e.g. after revoking a delegation). */
  clearCache(): void;
}

const DID = /^did:[a-z0-9]+:\S+$/;

export function createDidisGuard(options: DidisGuardOptions): DidisGuard {
  const { client, agent, root, pins = {}, requirePins = false, onDecision } = options;
  const allowCacheMs = options.allowCacheMs ?? 30_000;
  if (!client || typeof client.verifyTool !== "function") throw new DidisGuardError("GUARD_MISCONFIGURED", "", "a DidisClient is required");
  if (typeof agent !== "string" || !DID.test(agent)) throw new DidisGuardError("GUARD_MISCONFIGURED", "", "agent must be a DID");
  if (root !== undefined && (typeof root !== "string" || !DID.test(root))) throw new DidisGuardError("GUARD_MISCONFIGURED", "", "root must be a DID");
  if (!Number.isFinite(allowCacheMs) || allowCacheMs < 0) throw new DidisGuardError("GUARD_MISCONFIGURED", "", "allowCacheMs must be >= 0");
  for (const [name, pin] of Object.entries(pins)) {
    if (!/^[0-9a-f]{64}$/.test(pin)) throw new DidisGuardError("GUARD_MISCONFIGURED", name, "pins must be lowercase hex SHA-256");
  }
  const pinFor = (tool: string) => (Object.prototype.hasOwnProperty.call(pins, tool) ? pins[tool] : undefined);
  const allowed = new Map<string, number>();

  const report = (tool: string, ok: boolean, reason: string, cached: boolean, code?: DidisGuardErrorCode) => {
    try {
      onDecision?.({ tool, allowed: ok, code, reason, cached });
    } catch {
      /* audit hooks must not change the decision */
    }
  };
  const fail = (code: DidisGuardErrorCode, tool: string, reason: string, detail?: Record<string, unknown>): never => {
    report(tool, false, reason, false, code);
    throw new DidisGuardError(code, tool, reason, detail);
  };

  async function checkDefinition(tool: string, definition: Definition | undefined): Promise<void> {
    const pin = pinFor(tool);
    if (pin === undefined) {
      if (requirePins) fail("TOOL_DEFINITION_MISSING", tool, `no pinned definition for '${tool}'`);
      return;
    }
    let def: unknown;
    try {
      def = typeof definition === "function" ? await (definition as () => unknown)() : definition;
    } catch {
      return fail("TOOL_DEFINITION_MISSING", tool, `could not read the current definition of '${tool}'`);
    }
    if (def === undefined || def === null) fail("TOOL_DEFINITION_MISSING", tool, `'${tool}' is pinned but no definition was supplied`);
    let actual: string;
    try {
      actual = await toolDefinitionSha256(def);
    } catch {
      return fail("TOOL_DRIFT", tool, `the definition of '${tool}' is not valid JSON`);
    }
    if ((def as { name?: unknown }).name !== tool) fail("TOOL_DRIFT", tool, `definition name does not match '${tool}'`, { expected: pin, actual });
    if (actual !== pin) fail("TOOL_DRIFT", tool, `definition of '${tool}' changed since it was approved`, { expected: pin, actual });
  }

  async function checkDelegation(tool: string): Promise<void> {
    const now = Date.now();
    const until = allowed.get(tool);
    if (until !== undefined && until > now) {
      report(tool, true, "cached ALLOW", true);
      return;
    }
    allowed.delete(tool);
    let auth: ToolAuthorization;
    try {
      auth = await client.verifyTool(agent, tool, root);
    } catch (e) {
      const status = (e as { status?: number }).status;
      return fail("GUARD_UNAVAILABLE", tool, `DID.is verify-tool failed${status ? ` (HTTP ${status})` : ""}`, { status });
    }
    const exact = auth && auth.decision === "ALLOW" && auth.authorized === true && auth.agent === agent && auth.tool === tool;
    if (!exact) {
      if (auth && (auth.decision === "DENY" || auth.authorized === false)) {
        fail("TOOL_NOT_AUTHORIZED", tool, auth.reason || "delegation does not grant this tool", { matchedCapability: auth.matchedCapability });
      }
      fail("GUARD_UNAVAILABLE", tool, "DID.is returned an unexpected authorization answer");
    }
    if (root !== undefined && auth.root !== root) fail("TOOL_NOT_AUTHORIZED", tool, "delegation root does not match the configured root");
    if (allowCacheMs > 0) {
      const expires = auth.expires ? Date.parse(auth.expires) : NaN;
      const until2 = Math.min(now + allowCacheMs, Number.isFinite(expires) ? expires : now + allowCacheMs);
      if (until2 > now) allowed.set(tool, until2);
    }
    report(tool, true, auth.reason, false);
  }

  async function check({ tool, definition }: GuardCallOptions): Promise<void> {
    if (typeof tool !== "string" || !tool.trim() || tool !== tool.trim()) fail("GUARD_MISCONFIGURED", String(tool), "tool must be a non-empty, trimmed name");
    await checkDefinition(tool, definition);
    await checkDelegation(tool);
  }

  return {
    check,
    wrap<A extends unknown[], R>(call: GuardCallOptions, handler: (...args: A) => R | Promise<R>) {
      if (typeof handler !== "function") throw new DidisGuardError("GUARD_MISCONFIGURED", call?.tool ?? "", "handler must be a function");
      return async (...args: A): Promise<Awaited<R>> => {
        await check(call);
        return await handler(...args);
      };
    },
    clearCache() {
      allowed.clear();
    },
  };
}

/**
 * One-line form: `withDidisGuard(handler, { client, agent, root, tool, pin, definition })`.
 * For several tools, create one guard with `createDidisGuard` so the ALLOW cache is shared.
 */
export function withDidisGuard<A extends unknown[], R>(
  handler: (...args: A) => R | Promise<R>,
  options: Omit<DidisGuardOptions, "pins"> & GuardCallOptions & { pin?: string },
): (...args: A) => Promise<Awaited<R>> {
  const { tool, definition, pin, ...rest } = options;
  const guard = createDidisGuard({ ...rest, pins: pin ? { [tool]: pin } : undefined });
  return guard.wrap({ tool, definition }, handler);
}

export interface McpAttestation {
  ok: boolean;
  inventoryHash: string;
  /** Pinned tools whose DID.is-observed hash differs, or that DID.is did not see. */
  mismatched: { tool: string; expected: string; observed?: string }[];
  /** Tools DID.is saw that you have not pinned. */
  unpinned: string[];
  status: McpInspection["status"];
}

/**
 * Optional startup check: asks DID.is to inspect a public MCP endpoint and compares the observed
 * `definitionSha256` values with your pins. Use at deploy/startup, never per tool call.
 * `AUTH_REQUIRED` or any non-INSPECTED status returns `ok: false`.
 */
export async function attestMcpPins(client: DidisClient, endpoint: string, pins: Record<string, string>): Promise<McpAttestation> {
  const inspection = await client.inspectMcp(endpoint);
  const seen = new Map(inspection.tools.map((t) => [t.name, t.definitionSha256]));
  const mismatched = Object.entries(pins)
    .filter(([tool, expected]) => seen.get(tool) !== expected)
    .map(([tool, expected]) => ({ tool, expected, observed: seen.get(tool) }));
  const unpinned = [...seen.keys()].filter((t) => !Object.prototype.hasOwnProperty.call(pins, t));
  return {
    ok: inspection.status === "INSPECTED" && mismatched.length === 0,
    inventoryHash: inspection.inventoryHash,
    mismatched,
    unpinned,
    status: inspection.status,
  };
}
