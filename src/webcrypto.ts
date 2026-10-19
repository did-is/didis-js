/** WebCrypto: global in Node 19+, browsers, Deno, Bun and edge; Node 18 needs `node:crypto`. */
let cached: Promise<SubtleCrypto> | undefined;

export function subtle(): Promise<SubtleCrypto> {
  if (!cached) {
    const g = (globalThis as { crypto?: Crypto }).crypto;
    cached = g?.subtle
      ? Promise.resolve(g.subtle)
      : import("node:crypto" as string).then((m: { webcrypto?: Crypto }) => {
          if (!m.webcrypto?.subtle) throw new Error("WebCrypto is not available in this runtime");
          return m.webcrypto.subtle;
        });
    cached.catch(() => { cached = undefined; });
  }
  return cached;
}

/** Random UUID v4 for idempotency keys; Node 18 has no global `crypto`. */
export async function randomId(): Promise<string> {
  const g = (globalThis as { crypto?: Crypto }).crypto;
  if (g?.randomUUID) return g.randomUUID();
  const m = (await import("node:crypto" as string)) as { randomUUID?: () => string };
  if (!m.randomUUID) throw new Error("crypto.randomUUID is not available in this runtime");
  return m.randomUUID();
}
