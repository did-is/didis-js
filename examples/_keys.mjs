// Demo-only helpers: throwaway did:key principals and signed delegation receipts.
// Real deployments keep the root key offline and issue receipts from their own key management.
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const enc = new TextEncoder();
const b64url = (bytes) => Buffer.from(bytes).toString("base64url");

function base58btc(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) { carry += digits[i] << 8; digits[i] = carry % 58; carry = (carry / 58) | 0; }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = "";
  for (const b of bytes) { if (b !== 0) break; out += "1"; }
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}

/** A new Ed25519 did:key (public key multicodec 0xed01). */
export async function newPrincipal() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const id = "z" + base58btc(new Uint8Array([0xed, 0x01, ...raw]));
  return { did: `did:key:${id}`, kid: `did:key:${id}#${id}`, privateKey: pair.privateKey };
}

/** Delegation Receipt v1: `from` grants `capabilities` to `to`, optionally chained to `parent`. */
export async function signReceipt(from, to, capabilities, { notBefore, expires, parent } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "EdDSA", typ: "didis-delegation+jwt", kid: from.kid };
  const payload = {
    iss: from.did, aud: to.did, cap: capabilities,
    nbf: notBefore ?? now - 30, exp: expires ?? now + 3600,
    jti: `urn:uuid:${crypto.randomUUID()}`,
  };
  if (parent) {
    const digest = await crypto.subtle.digest("SHA-256", enc.encode(parent));
    payload.prf = Buffer.from(digest).toString("hex");
  }
  const input = `${b64url(enc.encode(JSON.stringify(header)))}.${b64url(enc.encode(JSON.stringify(payload)))}`;
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, from.privateKey, enc.encode(input));
  return `${input}.${b64url(new Uint8Array(sig))}`;
}
