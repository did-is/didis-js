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
