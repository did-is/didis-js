// Receive DID.is monitoring webhooks and verify them before acting. Zero dependencies besides the SDK.
//   WEBHOOK_SECRET=... TENANT_ID=tenant_... PROJECT_ID=project_... node webhook-receiver.mjs
//   node webhook-receiver.mjs --self-test     # signs a sample event locally and posts it to itself
import { createServer } from "node:http";
import { createHmac, randomBytes } from "node:crypto";
import { verifyCustomerMonitorSignature } from "@didis/client";

const selfTest = process.argv.includes("--self-test");
const hex = () => randomBytes(32).toString("hex");
const cfg = selfTest
  ? { secret: hex(), tenantId: `tenant_${hex()}`, projectId: `project_${hex()}` }
  : { secret: process.env.WEBHOOK_SECRET, tenantId: process.env.TENANT_ID, projectId: process.env.PROJECT_ID };
if (!cfg.secret || !cfg.tenantId || !cfg.projectId) {
  console.error("Set WEBHOOK_SECRET, TENANT_ID and PROJECT_ID (shown in the DID.is console), or use --self-test.");
  process.exit(2);
}

const seen = new Set(); // use a database table with a unique key in production

const server = createServer((req, res) => {
  if (req.method !== "POST" || req.url !== "/didis/webhook") { res.writeHead(404).end(); return; }
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const body = Buffer.concat(chunks).toString("utf8"); // the exact raw body
    const ok = await verifyCustomerMonitorSignature(cfg.secret, body, req.headers["x-didis-signature"] ?? "", {
      tenantId: cfg.tenantId, projectId: cfg.projectId, eventId: req.headers["x-didis-event-id"] ?? "",
    });
    if (!ok) { console.log("rejected: bad signature, too old, or not our project"); res.writeHead(401).end(); return; }
    const event = JSON.parse(body);
    if (seen.has(event.id)) { console.log(`duplicate ${event.id.slice(0, 15)}… ignored`); res.writeHead(200).end(); return; }
    seen.add(event.id); // record first, then act
    console.log(`accepted ${event.type} for watch ${event.watchId}`);
    res.writeHead(200).end();
  });
});

server.listen(Number(process.env.PORT ?? 8787), async () => {
  const { port } = server.address();
  console.log(`listening on port ${port}, POST /didis/webhook`);
  if (!selfTest) return;

  const url = `http://localhost:${port}/didis/webhook`;
  const event = {
    specVersion: "didis.customer-monitor.v1", id: `cevent_${hex()}`, tenantId: cfg.tenantId, projectId: cfg.projectId,
    watchId: "watch_demo", type: "document.changed", createdAt: Math.floor(Date.now() / 1000), data: {},
  };
  const body = JSON.stringify(event);
  const sign = (secret) => `t=${event.createdAt},v1=${createHmac("sha256", secret).update(`${event.createdAt}.${body}`).digest("hex")}`;
  const post = (signature, payload = body) => fetch(url, { method: "POST", body: payload,
    headers: { "content-type": "application/json", "x-didis-event-id": event.id, "x-didis-signature": signature } }).then((r) => r.status);

  console.log("genuine event      ->", await post(sign(cfg.secret)));
  console.log("same event again   ->", await post(sign(cfg.secret)));
  console.log("wrong secret       ->", await post(sign("not-the-secret")));
  console.log("body changed       ->", await post(sign(cfg.secret), body.replace("document.changed", "resolution.failed")));
  server.close();
});
