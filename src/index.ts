import { randomId, subtle } from "./webcrypto.js";
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

/** One `alsoKnownAs` value checked for a reciprocal link back to the DID. */
export interface LinkedAccountEvidence {
  /** The `alsoKnownAs` value exactly as declared. */
  value: string;
  /** `WEB_ORIGIN` | `WEB_PAGE` | `SAME_ORIGIN` | `DID` | `OTHER` */
  kind: string;
  origin?: string;
  /** `CONFIRMED` | `NOT_CONFIRMED` | `FAILED` | `UNSUPPORTED` | `UNREACHABLE` | `NOT_CHECKABLE` */
  status: string;
  configurationStatus?: string;
  configurationSha256?: string;
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
  /** Reciprocal checks of `alsoKnownAs`; absent when nothing is declared. */
  linkedAccounts?: LinkedAccountEvidence[];
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

export interface IssuerTrust {
  anchor: "DID" | "X509_CERTIFICATE" | "ISSUER_METADATA" | "NONE";
  result: "NOT_APPLICABLE" | "NOT_ESTABLISHED" | "CALLER_ANCHORED" | "CHAIN_INVALID";
  trustedListChecked: false;
  chain?: { sha256: string; subjectCn?: string; issuerCn?: string; notAfter?: string }[];
  metadataUrl?: string;
  proves: string;
  doesNotProve: string;
}

export interface SdJwtEvidence {
  sdAlg: string;
  disclosures: number;
  decoyDigests: number;
  registeredClaims: Record<string, unknown>;
  keyBinding: "VERIFIED" | "ABSENT" | "INVALID" | "UNSUPPORTED" | "INDETERMINATE";
}

export interface CredentialVerifyOptions {
  /** JWT `aud` / SD-JWT Key Binding `aud` constraint. */
  expectedAudience?: string;
  /** SD-JWT Key Binding `nonce` constraint; without it replay is not excluded. */
  expectedNonce?: string;
  /** Caller-chosen X.509 anchors (PEM or base64 DER) for SD-JWT VC `x5c`. Without them `x5c` is never VALID. */
  trustedIssuerCertificates?: string[];
  /**
   * Conditions checked without returning claim values, e.g. `[{ path: "/age_over_18", equals: true }]`.
   * Paths are JSON Pointers into the issuer-signed claims; `equals` is a boolean, integer or string.
   * Evaluated only for a VALID credential; see `CredentialVerification.requirements`.
   */
  requiredClaims?: ClaimRequirement[];
}

export interface ClaimRequirement {
  path: string;
  equals: boolean | number | string;
}

export interface RequirementsOutcome {
  /** True only when the credential is VALID and every condition is SATISFIED. */
  met: boolean;
  results: { path: string; result: "SATISFIED" | "NOT_SATISFIED" | "NOT_DISCLOSED" | "NOT_EVALUATED" }[];
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
  /** SD-JWT VC only. Categorical, never a score; EU trusted lists are never checked. */
  issuerTrust?: IssuerTrust;
  /** SD-JWT VC only. No disclosed claim values are ever returned. */
  sdJwt?: SdJwtEvidence;
  /** Present only when `requiredClaims` was sent. Never contains claim values. */
  requirements?: RequirementsOutcome;
  /** For SD-JWT VC: disclosed claim paths and digests only, never values. */
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

/** `GET /v1/customer/usage`: this month's team allowance (all of the team's projects share it). */
export interface CustomerUsage {
  period: string;
  standardUsed: number;
  standardReserved: number;
  standardLimit: number;
  standardRemaining: number;
  expensiveUsed: number;
  expensiveReserved: number;
  expensiveLimit: number;
  expensiveRemaining: number;
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
  /** 1–4 bare https origins that must be declared in `alsoKnownAs` and link back to the DID. */
  linkedAccounts?: string[];
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
  /**
   * Project API key from the DID.is console (optional). With a key, `inspectMcp`, `inspectA2a`,
   * `authorize` and `verifyDelegation` use the paid routes and count against your team's monthly
   * allowance instead of the anonymous per-IP limit. Results are identical. The key is sent only
   * to `/v1/customer/*` routes, never to public routes. Keep it server-side.
   */
  apiKey?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
  /**
   * Automatic wait-and-retry when the API answers 429 (request budget used up) or 503
   * (temporarily overloaded) with a `Retry-After` header. Such refusals happen before the
   * request is processed, so retrying is safe for every call. Default: up to 2 retries,
   * never waiting longer than 10 s for one retry. Pass `false` to turn it off.
   */
  retry?: false | { maxRetries?: number; maxWaitMs?: number };
}

/** Milliseconds to wait from a `Retry-After` value (delta-seconds or HTTP-date); null if unusable. */
export function retryAfterMs(value: string | null | undefined, now: number = Date.now()): number | null {
  if (!value) return null;
  const v = value.trim();
  if (/^\d+$/.test(v)) return Number(v) * 1000;
  const at = Date.parse(v);
  return Number.isNaN(at) ? null : Math.max(0, at - now);
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Public DID.is API. Point `baseUrl` at your own deployment when self-hosting. */
export const DEFAULT_BASE_URL = "https://did.is/api";

/** Package version, kept equal to package.json (checked by the test suite). */
export const VERSION = "0.2.5";

/**
 * Identifies the SDK to the API so DID.is can count SDK use apart from other HTTP clients.
 * Only the product name and version are sent. Browsers are left alone: there the browser
 * controls the user agent and an extra header would add a CORS preflight to every call.
 */
const SDK_HEADERS: Record<string, string> =
  typeof (globalThis as { document?: unknown }).document === "undefined" ? { "user-agent": `didis-client/${VERSION}` } : {};

const enc = (s: string) => encodeURIComponent(s.trim());

export class DidisClient {
  private readonly baseUrl: string;
  private readonly adminToken?: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly maxRetries: number;
  private readonly maxWaitMs: number;

  constructor(options: string | DidisClientOptions = {}) {
    const o: DidisClientOptions = typeof options === "string" ? { baseUrl: options } : options;
    this.baseUrl = (o.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.adminToken = o.adminToken;
    this.apiKey = o.apiKey || undefined;
    this.timeoutMs = o.timeoutMs ?? 30_000;
    this.fetchImpl = o.fetch ?? fetch;
    this.maxRetries = o.retry === false ? 0 : Math.max(0, Math.floor(o.retry?.maxRetries ?? 2));
    this.maxWaitMs = o.retry === false ? 0 : Math.max(0, o.retry?.maxWaitMs ?? 10_000);
  }

  /**
   * Waits out a 429/503 refusal when the server says how long, within the configured bounds.
   * A small random delay spreads out many clients that were refused at the same moment.
   */
  private async backoff(attempt: number, status: number, retryAfter: string | null): Promise<boolean> {
    if (attempt >= this.maxRetries || (status !== 429 && status !== 503)) return false;
    const wait = retryAfterMs(retryAfter);
    if (wait === null || wait > this.maxWaitMs) return false;
    await sleep(wait + Math.floor(Math.random() * 250));
    return true;
  }

  private async request<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.once<T>(method, path, body, headers);
      } catch (e) {
        if (!(e instanceof DidisError) || !(await this.backoff(attempt, e.status, e.problem.retryAfter ?? null))) throw e;
      }
    }
  }

  private async once<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        signal: controller.signal,
        headers: { ...SDK_HEADERS, accept: "application/json", ...(body !== undefined ? { "content-type": "application/json" } : {}), ...headers },
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

  /**
   * Paid route call: the project API key plus one fresh Idempotency-Key. Automatic retries of a
   * 429/503 reuse the same key, so a request is never billed twice.
   */
  private async paid<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers = { authorization: `Bearer ${this.apiKey}`, ...(method === "POST" ? { "idempotency-key": await randomId() } : {}) };
    return this.request<T>(method, `/v1/customer/${path}`, body, headers);
  }

  /** Team allowance for this month (requires `apiKey`). Same numbers as the RateLimit headers. */
  usage(): Promise<CustomerUsage> {
    if (!this.apiKey) return Promise.reject(new Error("apiKey is required for usage()"));
    return this.paid("GET", "usage");
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
      headers: { ...SDK_HEADERS, accept: "text/event-stream" },
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
  verifyCredential(credential: unknown, options: CredentialVerifyOptions = {}): Promise<CredentialVerification> {
    return this.request("POST", "/v1/credentials/verify", {
      credential,
      expectedAudience: options.expectedAudience,
      expectedNonce: options.expectedNonce,
      trustedIssuerCertificates: options.trustedIssuerCertificates,
      requiredClaims: options.requiredClaims,
    });
  }

  evaluatePolicy(did: string, policy: { name?: string; rules: PolicyRules }, credential?: unknown): Promise<PolicyResponse> {
    return this.request("POST", "/v1/policies/evaluate", { did, policy, credential });
  }

  inspectMcp(endpoint: string): Promise<McpInspection> {
    if (this.apiKey) return this.paid("POST", "mcp/inspect", { endpoint });
    return this.request("GET", `/v1/mcp/inspect?endpoint=${encodeURIComponent(endpoint)}`);
  }

  inspectA2a(url: string): Promise<A2aInspection> {
    if (this.apiKey) return this.paid("POST", "a2a/inspect", { url });
    return this.request("GET", `/v1/a2a/inspect?url=${encodeURIComponent(url)}`);
  }

  /**
   * `register: true` stores the chain for `verifyTool`; it always uses the public route (the paid
   * route never writes shared state), so the API key is not sent for it.
   */
  verifyDelegation(chain: string[], opts: { trustedRoots?: string[]; register?: boolean } = {}): Promise<DelegationVerification> {
    if (this.apiKey && !opts.register) {
      return this.paid("POST", "agents/verify-delegation", { chain, ...(opts.trustedRoots ? { trustedRoots: opts.trustedRoots } : {}) });
    }
    return this.request("POST", "/v1/agents/verify-delegation", { chain, ...opts });
  }

  authorize(chain: string[], tool: string, opts: { trustedRoots?: string[] } = {}): Promise<AuthorizationResponse> {
    if (this.apiKey) return this.paid("POST", "agents/authorize", { chain, tool, ...(opts.trustedRoots ? { trustedRoots: opts.trustedRoots } : {}) });
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
  const key = await (await subtle()).importKey("raw", te.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await (await subtle()).sign("HMAC", key, te.encode(`${timestamp}.${body}`)));
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
    const key = await (await subtle()).importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const mac = Uint8Array.from(match[2].match(/../g)!, value => parseInt(value, 16));
    if (!await (await subtle()).verify("HMAC", key, mac, new TextEncoder().encode(`${match[1]}.${body}`))) return false;
    const event = JSON.parse(body);
    return event.specVersion === "didis.customer-monitor.v1" && event.createdAt === timestamp
      && /^cevent_[0-9a-f]{64}$/.test(expected.eventId) && event.id === expected.eventId
      && /^tenant_[0-9a-f]{64}$/.test(expected.tenantId) && event.tenantId === expected.tenantId
      && /^project_[0-9a-f]{64}$/.test(expected.projectId) && event.projectId === expected.projectId;
  } catch { return false; }
}
export * from "./guard.js";
