/**
 * DID.is client SDK (TypeScript — Node 18+, Deno, Bun, browsers, edge runtimes).
 *
 * Every identifier is percent-encoded exactly once; the resolver decodes it exactly once.
 * Errors are thrown as `DidisError`, carrying the RFC 9457 problem object returned by the API.
 */

// ---------------------------------------------------------------------------------------------
// Wire types (camelCase JSON, mirroring the public DID.is API; see https://did.is/developers)
// String-union fields keep `| string` where the server may add states in a minor release.
// ---------------------------------------------------------------------------------------------

export type DimensionState =
  | "ESTABLISHED"
  | "SELF_CERTIFYING"
  | "NOT_ESTABLISHED"
  | "FAILED"
  | "INDETERMINATE"
  | "NOT_APPLICABLE";

export interface Problem {
  type: string;
  title: string;
  status?: number;
  detail: string;
  code?: string;
  trace?: TraceStage[];
  /** Retry-After delta-seconds or HTTP-date, verbatim from the server. */
  retryAfter?: string;
}

export interface TraceStage {
  stage: string;
  label: string;
  status: "PASS" | "FAIL" | "WARN" | "INFO" | "SKIP" | string;
  startedUs: number;
  durationUs: number;
  detail: string;
}

export interface ResolutionMetadata {
  contentType?: string;
  error?: Problem;
  retrieved?: string;
  durationMs?: number;
}

export interface ResolutionSource {
  kind: "LOCAL_DERIVATION" | "HTTPS" | string;
  url?: string;
  httpStatus?: number;
  contentType?: string;
  bytes?: number;
  sha256?: string;
  peerAddress?: string;
  redirects?: string[];
  latencyMs: number;
}

export interface CertificateSummary {
  sha256Fingerprint: string;
  subjectCn?: string;
  subjectO?: string;
  issuerCn?: string;
  issuerO?: string;
  notBefore?: string;
  notAfter?: string;
  serialHex?: string;
  sanDns: string[];
}

export interface TlsEvidence {
  host: string;
  validatedBy: string;
  protocol: string;
  certificate?: CertificateSummary;
  daysUntilExpiry?: number;
  hostnameInSan?: boolean;
}

export interface MulticodecBreakdown {
  multibasePrefix: string;
  multibaseEncoding: string;
  codec: string;
  codecName: string;
  varintHex: string;
  keyBytesHex: string;
  keyLength: number;
}

export interface KeyEvidence {
  id: string;
  type: string;
  controller?: string;
  controllerIsSubject: boolean;
  relationships: string[];
  materialProperty?: string;
  status: "VALID_KEY" | "INVALID_KEY" | "UNSUPPORTED_KEY" | string;
  curve?: string;
  keySizeBits?: number;
  jwkThumbprint?: string;
  multikey?: string;
  jwk?: Record<string, unknown>;
  multicodec?: MulticodecBreakdown;
  detail: string;
}

export interface ServiceEvidence {
  id: string;
  type: unknown;
  endpoint: unknown;
  notes: string[];
}

export interface DocumentEvidence {
  idMatches: boolean;
  contexts: { uri: string; known: boolean; name?: string }[];
  verificationMethodCount: number;
  serviceCount: number;
  relationships: Record<string, string[]>;
  alsoKnownAs: string[];
  controllers: string[];
  jcsSha256?: string;
  jcsProfile?: string;
  warnings: string[];
}

export interface LinkageCredentialEvidence {
  format: string;
  issuer?: string;
  subject?: string;
  origin?: string;
  verificationMethod?: string;
  proofSuite?: string;
  issuanceDate?: string;
  expirationDate?: string;
  status: string;
  detail: string;
}

export interface DomainBindingEvidence {
  status: string;
  origin: string;
  configurationUrl: string;
  httpStatus?: number;
  configurationSha256?: string;
  linkedDids: string[];
  credentials: LinkageCredentialEvidence[];
  detail: string;
}

export interface LogEntryEvidence {
  versionId: string;
  versionNumber: number;
  versionTime: string;
  entryHash: string;
  entryHashValid: boolean;
  proofValid: boolean;
  signer?: string;
  updateKeys: string[];
  parametersChanged: string[];
  stateSha256?: string;
  detail: string;
}

export interface HistoryEvidence {
  scid: string;
  logUrl: string;
  logSha256: string;
  entries: LogEntryEvidence[];
  selectedVersionId: string;
  preRotation: boolean;
  portable: boolean;
  deactivated: boolean;
  witness?: { threshold: number; witnesses: string[]; approvals: number; satisfied: boolean; detail: string };
  ttl?: number;
}

export interface EvidenceDimension {
  id: string;
  label: string;
  state: DimensionState;
  statement: string;
  proves: string;
  doesNotProve: string;
}

export interface Verdict {
  outcome: "RESOLVED" | "RESOLVED_WITH_WARNINGS" | "DEACTIVATED" | string;
  headline: string;
  statements: string[];
}

export interface GraphNode {
  id: string;
  kind: string;
  label: string;
  sublabel?: string;
  state: string;
  layer: number;
  digest?: string;
  facts: [string, string][];
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  relation: string;
  state: "VERIFIED" | "OBSERVED" | "DECLARED" | "FAILED" | string;
}

export interface Evidence {
  source: ResolutionSource;
  document: DocumentEvidence;
  keys: KeyEvidence[];
  services: ServiceEvidence[];
  domainBinding?: DomainBindingEvidence;
  tls?: TlsEvidence;
  history?: HistoryEvidence;
}

export interface EnrichedResolution {
  did: string;
  method: string;
  didDocument: Record<string, unknown> | null;
  didResolutionMetadata: ResolutionMetadata;
  didDocumentMetadata: Record<string, unknown>;
  verdict: Verdict;
  dimensions: EvidenceDimension[];
  evidence: Evidence;
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  trace: TraceStage[];
  limitations: string[];
  resolver: { name: string; version: string };
  observedAt: string;
  cached: boolean;
}

export interface Check {
  id: string;
  label: string;
  status: "PASS" | "FAIL" | "WARN" | "SKIP" | "UNSUPPORTED" | "INDETERMINATE" | string;
  detail: string;
}

export interface CredentialVerification {
  status: string;
  headline: string;
  format: string;
  dataModel: string;
  id?: string;
  issuer?: string;
  issuerName?: string;
  subject?: string;
  types: string[];
  validFrom?: string;
  validUntil?: string;
  checks: Check[];
  proof?: {
    format: string;
    suite?: string;
    verificationMethod?: string;
    proofPurpose?: string;
    created?: string;
    keyCurve?: string;
    signedDigest?: string;
    detail: string;
  };
  statusList: {
    id?: string;
    statusType: string;
    purpose: string;
    index?: number;
    listUrl?: string;
    statusSize: number;
    listCredentialVerified?: boolean;
    listLengthBits?: number;
    value?: number;
    result: string;
    window?: string;
    windowOffset?: number;
    detail: string;
  }[];
  issuerResolution?: { id: string; outcome?: string; headline?: string; domainBinding?: string; detail: string };
  claims: unknown;
  credential: unknown;
  limitations: string[];
  valid: boolean;
  errors: string[];
}

export interface ToolEvidence {
  name: string;
  title?: string;
  description: string;
  definitionSha256: string;
  schemaSha256: string;
  parameters: string[];
  annotations: unknown;
  declaredClass?: string;
  heuristicClass: string;
  riskSignals: string[];
  drift: string;
  inputSchema: unknown;
}

export interface McpInspection {
  endpoint: string;
  status: "INSPECTED" | "AUTH_REQUIRED" | string;
  mode: string;
  negotiatedVersion?: string;
  supportedVersions: string[];
  serverInfo: Record<string, unknown> | null;
  capabilities: unknown;
  instructions?: string;
  tools: ToolEvidence[];
  inventoryHash: string;
  jcsProfile?: string;
  classCounts: Record<string, number>;
  drift: { status: string; previousObservedAt?: string; previousInventoryHash?: string; added: string[]; removed: string[]; changed: string[] };
  auth?: { required: boolean; wwwAuthenticate?: string; resourceMetadata?: string };
  transcript: { method: string; httpStatus?: number; contentType?: string; latencyMs: number; outcome: string }[];
  checks: Check[];
  headline: string;
  tls?: TlsEvidence;
  limitations: string[];
}

export interface A2aInspection {
  cardUrl: string;
  httpStatus: number;
  cardSha256: string;
  canonicalSha256: string;
  jcsProfile?: string;
  specVersion: string;
  name: string;
  description: string;
  version?: string;
  provider?: { organization?: string; url?: string };
  documentationUrl?: string;
  interfaces: { url: string; protocolBinding: string; protocolVersion?: string; https: boolean; sameOrigin: boolean }[];
  capabilities: Record<string, unknown> | null;
  securitySchemes: { name: string; kind: string; detail: string }[];
  skills: { id: string; name: string; description: string; tags: string[]; examples: string[] }[];
  signatures: { alg?: string; kid?: string; jku?: string; status: string; detail: string }[];
  checks: Check[];
  headline: string;
  card: unknown;
  tls?: TlsEvidence;
  limitations: string[];
}

export interface DelegationLink {
  index: number;
  issuer: string;
  audience: string;
  capabilities: string[];
  notBefore?: string;
  expires?: string;
  jti?: string;
  kid?: string;
  alg?: string;
  digest: string;
  signatureValid: boolean;
  status: string;
  issuerHeadline?: string;
  checks: Check[];
}

export interface DelegationChainResult {
  status: string;
  headline: string;
  format: string;
  root?: string;
  leaf?: string;
  effectiveCapabilities: string[];
  notAfter?: string;
  trustedRoot?: boolean;
  links: DelegationLink[];
  checks: Check[];
  limitations: string[];
}

export interface ToolAuthorization {
  agent: string;
  tool: string;
  decision: "ALLOW" | "DENY";
  authorized: boolean;
  reason: string;
  matchedCapability?: string;
  root?: string;
  expires?: string;
}

export interface PolicyRuleEvaluation {
  rule: string;
  status: "PASS" | "FAIL" | "INDETERMINATE" | "NOT_APPLICABLE";
  message: string;
  expected?: unknown;
  observedValue?: unknown;
}

export interface PolicyEvaluation {
  did: string;
  policyName?: string;
  status: "PASS" | "FAIL" | "INDETERMINATE" | "NOT_APPLICABLE";
  headline: string;
  rulesEvaluated: number;
  rulesPassed: number;
  evaluations: PolicyRuleEvaluation[];
  evaluatedAt: string;
}

export interface ObservationRecord {
  id: number;
  did: string;
  documentHash: string;
  observedAt: string;
  lastSeenAt: string;
  seenCount: number;
  latencyMs: number;
  resolverVersion: string;
  domainBindingStatus: string;
  summary: { outcome?: string; headline?: string } | null;
}

export interface SemanticDiff {
  did: string;
  fromHash: string;
  toHash: string;
  fromObservedAt: string;
  toObservedAt: string;
  identical: boolean;
  keysAdded: string[];
  keysRemoved: string[];
  keysRotated: string[];
  relationshipsChanged: { relationship: string; added: string[]; removed: string[] }[];
  servicesAdded: string[];
  servicesRemoved: string[];
  servicesChanged: string[];
  controllerChanged: boolean;
  alsoKnownAsChanged: boolean;
  contextsChanged: boolean;
  domainBindingFrom: string;
  domainBindingTo: string;
  domainBindingChanged: boolean;
  changedMembers: string[];
  summary: string[];
  fromDocument: unknown;
  toDocument: unknown;
}

export interface ResolutionResult {
  "@context": string;
  didDocument: Record<string, unknown> | null;
  didResolutionMetadata: ResolutionMetadata;
  didDocumentMetadata: Record<string, unknown>;
}

export interface DereferencingResult {
  "@context": string;
  dereferencingMetadata: ResolutionMetadata;
  contentStream: unknown;
  contentMetadata: Record<string, unknown>;
}

export interface PolicyRules {
  didResolution?: "required" | "optional";
  allowedMethods?: string[];
  allowedCurves?: string[];
  allowedKeySuites?: string[];
  minKeyBits?: number;
  requireKeyRelationship?: string;
  domainBinding?: "required" | "optional";
  tlsMinDaysRemaining?: number;
  verifiableHistory?: "required";
  maxCacheAgeSeconds?: number;
  credentialStatus?: "active";
  credentialIssuerMustBeSubject?: boolean;
}

export interface PolicyResponse {
  evaluation: PolicyEvaluation;
  credential: CredentialVerification | null;
  resolution: { verdict: Verdict; dimensions: EvidenceDimension[] } | null;
}

export interface HealthStatus {
  status: "ok" | string;
  name: string;
  version: string;
  time: string;
  supportedMethods: string[];
  standards: Record<string, unknown>;
  monitoring?: boolean;
  rateLimited?: boolean;
}

export interface HistoryResponse {
  did: string;
  count: number;
  history: ObservationRecord[];
  note: string;
}

export interface GraphResponse {
  did: string;
  observedAt: string;
  verdict: Verdict;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface FastVerifyDidResult {
  did: string;
  resolved: boolean;
  outcome: Verdict["outcome"];
  headline: string;
  statements: string[];
  dimensions: { id: string; state: DimensionState }[];
  keys: { id: string; curve?: string; status: KeyEvidence["status"]; relationships: string[]; jwkThumbprint?: string }[];
  domainBinding: string | null;
  documentSha256?: string;
  observedAt: string;
  cached: boolean;
}

export interface FastVerifyJwsResult {
  status: "VALID" | "INVALID" | "INDETERMINATE" | "UNSUPPORTED" | "MALFORMED";
  valid: boolean;
  headline: string;
  alg?: string;
  kid?: string;
  typ?: string;
  /** Decoded JSON payload, or base64url text when the payload is not JSON. */
  payload?: unknown;
  signingInputSha256?: string;
  signer?: string;
  relationship?: string;
}

export interface DelegationVerification {
  result: DelegationChainResult;
  registered: boolean;
}

export interface AuthorizationResponse {
  authorization: ToolAuthorization;
  chain: DelegationChainResult;
}

export type StreamEvent =
  | { event: "stage"; data: TraceStage }
  | { event: "result"; data: EnrichedResolution }
  | { event: "error"; data: Problem }
  | { event: "done"; data: Record<string, never> };

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

export class DidisError extends Error {
  readonly problem: Problem;
  readonly status: number;

  constructor(status: number, problem: Problem) {
    super(`${problem.title}: ${problem.detail}`);
    this.name = "DidisError";
    this.status = status;
    this.problem = problem;
  }
}

export interface DidisClientOptions {
  baseUrl?: string;
  /** Bearer token for admin-only monitoring routes. Never ship it to browsers. */
  adminToken?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

/** Public DID.is API. Point `baseUrl` at your own deployment when self-hosting. */
export const DEFAULT_BASE_URL = "https://did.is/api";

const enc = (s: string) => encodeURIComponent(s.trim());

export class DidisClient {
  private readonly baseUrl: string;
  private readonly adminToken?: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: string | DidisClientOptions = {}) {
    const o: DidisClientOptions = typeof options === "string" ? { baseUrl: options } : options;
    this.baseUrl = (o.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.adminToken = o.adminToken;
    this.timeoutMs = o.timeoutMs ?? 30_000;
    this.fetchImpl = o.fetch ?? fetch;
  }

  private async request<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        signal: controller.signal,
        headers: { accept: "application/json", ...(body !== undefined ? { "content-type": "application/json" } : {}), ...headers },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const text = await res.text();
      const json = text ? JSON.parse(text) : null;
      if (!res.ok) {
        const p = (json ?? {}) as Partial<Problem>;
        throw new DidisError(res.status, {
          type: p.type ?? "about:blank",
          title: p.title ?? `HTTP ${res.status}`,
          status: res.status,
          detail: p.detail ?? text,
          code: p.code,
          trace: p.trace,
          retryAfter: res.headers.get("retry-after") ?? undefined,
        });
      }
      return json as T;
    } finally {
      clearTimeout(timer);
    }
  }

  private admin(): Record<string, string> {
    if (!this.adminToken) throw new Error("adminToken is required for monitoring routes");
    return { authorization: `Bearer ${this.adminToken}` };
  }

  health(): Promise<HealthStatus> {
    return this.request("GET", "/health");
  }

  /** Enriched resolution: verdict, evidence dimensions, graph, telemetry. */
  resolve(did: string, opts: { noCache?: boolean } = {}): Promise<EnrichedResolution> {
    return this.request("GET", `/v1/resolve/${enc(did)}${opts.noCache ? "?noCache=true" : ""}`);
  }

  /** DID Resolution v1 HTTPS binding (W3C CR Draft; full resolution result). */
  resolveW3c(did: string): Promise<ResolutionResult> {
    return this.request("GET", `/1.0/identifiers/${enc(did)}`, undefined, { accept: "application/did-resolution" });
  }

  dereference(didUrl: string): Promise<DereferencingResult> {
    return this.request("GET", `/v1/dereference/${enc(didUrl)}`);
  }

  /** Live resolution over server-sent events. */
  async *stream(did: string, opts: { noCache?: boolean } = { noCache: true }): AsyncGenerator<StreamEvent> {
    const res = await this.fetchImpl(`${this.baseUrl}/v1/stream/${enc(did)}${opts.noCache ? "?noCache=true" : ""}`, {
      headers: { accept: "text/event-stream" },
    });
    if (!res.ok || !res.body) throw new DidisError(res.status, { type: "about:blank", title: `HTTP ${res.status}`, detail: "stream failed" });
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buffer.indexOf("\n\n")) >= 0) {
        const block = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        let event = "message";
        const data: string[] = [];
        for (const line of block.split("\n")) {
          if (line.startsWith("event:")) event = line.slice(6).trim();
          else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
        }
        if (data.length === 0) continue;
        const raw = data.join("\n");
        let parsed: unknown = raw;
        try {
          parsed = JSON.parse(raw);
        } catch {
          /* non-JSON payload */
        }
        yield { event, data: parsed } as StreamEvent;
        if (event === "done") return;
      }
    }
  }

  history(did: string): Promise<HistoryResponse> {
    return this.request("GET", `/v1/history/${enc(did)}`);
  }

  /** Semantic diff; defaults to the latest two distinct observations. */
  diff(did: string, from?: string, to?: string): Promise<SemanticDiff> {
    const q = from && to ? `?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}` : "";
    return this.request("GET", `/v1/diff/${enc(did)}${q}`);
  }

  graph(did: string): Promise<GraphResponse> {
    return this.request("GET", `/v1/graph/${enc(did)}`);
  }

  /** Audience is checked only when an expected recipient is supplied. Pass raw JSON as a string to preserve member identity. */
  verifyCredential(credential: unknown, options: { expectedAudience?: string } = {}): Promise<CredentialVerification> {
    return this.request("POST", "/v1/credentials/verify", { credential, expectedAudience: options.expectedAudience });
  }

  evaluatePolicy(did: string, policy: { name?: string; rules: PolicyRules }, credential?: unknown): Promise<PolicyResponse> {
    return this.request("POST", "/v1/policies/evaluate", { did, policy, credential });
  }

  inspectMcp(endpoint: string): Promise<McpInspection> {
    return this.request("GET", `/v1/mcp/inspect?endpoint=${encodeURIComponent(endpoint)}`);
  }

  inspectA2a(url: string): Promise<A2aInspection> {
    return this.request("GET", `/v1/a2a/inspect?url=${encodeURIComponent(url)}`);
  }

  verifyDelegation(chain: string[], opts: { trustedRoots?: string[]; register?: boolean } = {}): Promise<DelegationVerification> {
    return this.request("POST", "/v1/agents/verify-delegation", { chain, ...opts });
  }

  authorize(chain: string[], tool: string, opts: { trustedRoots?: string[] } = {}): Promise<AuthorizationResponse> {
    return this.request("POST", "/v1/agents/authorize", { chain, tool, ...opts });
  }

  verifyTool(agent: string, tool: string, root?: string): Promise<ToolAuthorization> {
    const q = new URLSearchParams({ agent, tool, ...(root ? { root } : {}) });
    return this.request("GET", `/v1/agents/verify-tool?${q.toString()}`);
  }

  fastVerifyDid(did: string): Promise<FastVerifyDidResult> {
    return this.request("GET", `/v1/fast-verify/did/${enc(did)}`);
  }

  fastVerifyJws(jws: string, relationship?: string): Promise<FastVerifyJwsResult> {
    return this.request("POST", "/v1/fast-verify/jws", { jws, relationship });
  }

  // ---- Monitoring (admin) ------------------------------------------------------------------

  async watch(did: string, webhookUrl: string, intervalSeconds?: number): Promise<{ watch: Record<string, unknown>; secret: string }> {
    return this.request("POST", "/v1/monitoring/watches", { did, webhookUrl, intervalSeconds }, this.admin());
  }

  async watches(): Promise<{ watches: Record<string, unknown>[] }> {
    return this.request("GET", "/v1/monitoring/watches", undefined, this.admin());
  }

  async unwatch(id: string): Promise<null> {
    return this.request("DELETE", `/v1/monitoring/watches/${encodeURIComponent(id)}`, undefined, this.admin());
  }

  async events(watchId?: string): Promise<{ events: Record<string, unknown>[] }> {
    return this.request("GET", `/v1/monitoring/events${watchId ? `?watchId=${encodeURIComponent(watchId)}` : ""}`, undefined, this.admin());
  }
}

/**
 * Verifies a webhook delivery: `X-Didis-Signature-256 = sha256=HMAC(secret, timestamp + "." + body)`.
 * Rejects deliveries older than `toleranceSeconds`. Uses WebCrypto (Node 18+, browsers, edge).
 */
export async function verifyWebhookSignature(secret: string, timestamp: string, body: string, signatureHeader: string, toleranceSeconds = 300): Promise<boolean> {
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > toleranceSeconds) return false;
  const te = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", te.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, te.encode(`${timestamp}.${body}`)));
  const expected = `sha256=${Array.from(mac, (b) => b.toString(16).padStart(2, "0")).join("")}`;
  if (expected.length !== signatureHeader.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signatureHeader.charCodeAt(i);
  return diff === 0;
}

/** Verifies the separate durable CUSTOMER event signature, not the admin webhook format.
 * The timestamp is event creation and remains unchanged on retry. The receiver MUST persist
 * event-ID deduplication before side effects. A valid signature is not a billing grant.
 */
export async function verifyCustomerMonitorSignature(secret: string, body: string, signature: string, expected: { tenantId: string; projectId: string; eventId: string }, maxAgeSeconds = 30 * 86400): Promise<boolean> {
  const match = /^t=(0|[1-9][0-9]{0,15}),v1=([0-9a-f]{64})$/.exec(signature);
  const timestamp = match ? Number(match[1]) : NaN;
  const now = Date.now() / 1000;
  const bytes = new TextEncoder().encode(body);
  if (!match || !Number.isSafeInteger(timestamp) || !Number.isInteger(maxAgeSeconds) || maxAgeSeconds < 1 || maxAgeSeconds > 30 * 86400 || timestamp > now + 60 || now - timestamp >= maxAgeSeconds || bytes.length > 300 * 1024 || !secret) return false;
  try {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const mac = Uint8Array.from(match[2].match(/../g)!, value => parseInt(value, 16));
    if (!await crypto.subtle.verify("HMAC", key, mac, new TextEncoder().encode(`${match[1]}.${body}`))) return false;
    const event = JSON.parse(body);
    return event.specVersion === "didis.customer-monitor.v1" && event.createdAt === timestamp
      && /^cevent_[0-9a-f]{64}$/.test(expected.eventId) && event.id === expected.eventId
      && /^tenant_[0-9a-f]{64}$/.test(expected.tenantId) && event.tenantId === expected.tenantId
      && /^project_[0-9a-f]{64}$/.test(expected.projectId) && event.projectId === expected.projectId;
  } catch { return false; }
}
