#!/usr/bin/env node
// Fetches an agent card with the a2a-js card resolver and prints one JSON result line per mode.
// Usage: node check_js.mjs SDK_DIR CARD_URL
// SDK_DIR holds node_modules/@a2a-js/sdk (0.3.x or 1.x). The optional SDK_CHECK_BEARER environment
// variable is sent as a bearer token and never printed. The 1.x SDK is run twice, without and with
// its legacy compatibility layer, because the 0.3 card shape is only translated when it is on.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [sdkDir, cardUrl] = process.argv.slice(2);
const sdkPackage = join(sdkDir, "node_modules", "@a2a-js", "sdk");
const version = JSON.parse(readFileSync(join(sdkPackage, "package.json"), "utf8")).version;
const clientModule = await import(pathToFileURL(createRequire(join(sdkDir, "x.js")).resolve("@a2a-js/sdk/client")).href);
const token = process.env.SDK_CHECK_BEARER;

const fetchImpl = (input, init = {}) => {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return fetch(input, { ...init, headers });
};

const parts = new URL(cardUrl);
const base = parts.origin;
const path = parts.pathname + parts.search;

const flowNames = (flows) =>
  flows?.flow ? [flows.flow.$case] : Object.keys(flows ?? {}).filter((k) => flows[k]).sort();

const flowBody = (flows, name) => (flows?.flow ? flows.flow.value : flows[name]);

function unwrapScheme(raw) {
  if (raw.scheme?.$case) {
    return { shape: "native", kind: raw.scheme.$case.replace(/SecurityScheme$/, ""), body: raw.scheme.value };
  }
  if (raw.type) return { shape: "flat", kind: raw.type, body: raw };
  const key = Object.keys(raw)[0];
  return { shape: "wrapped", kind: key.replace(/SecurityScheme$/, ""), body: raw[key] };
}

function summarize(card) {
  const schemes = {};
  const shapes = new Set();
  for (const [name, raw] of Object.entries(card.securitySchemes ?? {})) {
    const { shape, kind, body } = unwrapScheme(raw);
    shapes.add(shape);
    const names = flowNames(body.flows);
    schemes[name] = {
      type: kind,
      metadataUrl: body.oauth2MetadataUrl ?? null,
      flows: names,
      scopes: [...new Set(names.flatMap((f) => Object.keys(flowBody(body.flows, f)?.scopes ?? {})))].sort(),
    };
  }
  const requirements = (card.securityRequirements ?? card.security ?? []).map((req) => {
    const entries = req.schemes ?? req;
    return Object.fromEntries(Object.entries(entries).map(([k, v]) => [k, [...(v.list ?? v)].sort()]));
  });
  const interfaces = card.supportedInterfaces?.map((i) => i.url) ?? [card.url];
  return { name: card.name, interfaces, schemes, requirements, schemeShape: [...shapes].sort().join(",") || null };
}

async function run(mode, options) {
  const result = { sdk: "a2a-js", version, mode };
  try {
    const resolver = new clientModule.DefaultAgentCardResolver({ fetchImpl, ...options });
    const card = await resolver.resolve(base, path);
    Object.assign(result, { ok: true, summary: summarize(card) });
  } catch (error) {
    Object.assign(result, { ok: false, error: `${error?.name ?? "Error"}: ${error?.message ?? error}`.slice(0, 600) });
  }
  console.log(JSON.stringify(result));
}

await run("default", {});
if (version.startsWith("1.")) await run("legacy-compat", { legacyCompat: { enabled: true } });
