#!/usr/bin/env node
// ---------------------------------------------------------------------------
// SBOB-EXAMPLES DEMO WATERMARK — scenario D harness: LIVE-telemetry replay.
//
// Replays the harness-captured auditd windows (scenarios/nginx2root/telemetry
// capture, see harness/run-behaviors.sh) through the Wazuh server logtest
// API (PUT /logtest, session tokens reused so firedtimes accumulate), the
// same API surface Software-Bill-of-Behavior's scripts/logtest-api.ts uses
// for the recorded corpora. That script is --target-driven with corpus paths
// fixed inside the SBoB repo; this vendored variant is file-driven so the
// LIVE captures can be replayed with the same assertion semantics:
//
//   benign mode: replay the window `--repeats` times in ONE session and
//     assert ZERO alerts (level-0 base-chain matches are fine, and the
//     sustained children must stay silent too — they chain from drift
//     rules that benign lines can never match). An EMPTY window is the
//     honest node-side-observer shape (delta 7: the exe-scoped keys cannot
//     tag the containerized workload, so benign declared behavior is
//     untagged) and passes vacuously: there is nothing that could fire.
//   drift mode: replay the window once and assert every --expect rule id
//     fired and every --expect-absent rule id did NOT (the recorded
//     delta-7 gap: exe-scoped rules cannot tag the containerized workload
//     node-side, so the live drift window fires only the node-scoped
//     signature rule); then replay it `--repeats` times in ONE session and
//     assert every --expect-sustained frequency child fired (8/120s)
//
// Exit codes: 0 = pass, 1 = detection assertion failed, 2 = usage/transport.
// Zero dependencies, Node >= 22 (type stripping), mirroring the proven
// transport/parsing logic of scripts/logtest-api.ts at the pinned SBoB SHA.
//
// Usage:
//   node logtest-replay.ts --api https://localhost:55000 --pass wazuh \
//     --file telemetry/benign.audit --mode benign --repeats 8
//   node logtest-replay.ts --api https://localhost:55000 --pass wazuh \
//     --file telemetry/drift.audit --mode drift \
//     --expect 100463 --expect-absent 100411,100421,100431 --repeats 8
// ---------------------------------------------------------------------------
import { readFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { pathToFileURL } from "node:url";

// ---------------------------------------------------------------------------
// pure helpers (same semantics as the SBoB repo's logtest-api.ts)
// ---------------------------------------------------------------------------

export function corpusLines(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

function dataOf(resp: unknown): Record<string, unknown> {
  const r = asRecord(resp);
  if (r === null) return {};
  return asRecord(r["data"]) ?? r;
}

// rule record from data.rule, data.alert.rule, or data.output.rule — the
// 4.14 session reply nests the matched rule under `output` as an OBJECT
// (reply shape replica-verified on wazuh-manager 4.14.6:
//  {data:{alert:true, codemsg:0, output:{decoder, data, rule:{id:"100463"...}}}});
// the array-of-strings fallback in extractRuleId only covers the CLI text
// spelling, which the API session reply does not use — without this branch
// every structured reply extracts as "no rule fired" and drift assertions
// fail vacuously (the exact defect run 44589490713 tripped)
function ruleRecordOf(data: Record<string, unknown>): Record<string, unknown> | null {
  const rule = asRecord(data["rule"]);
  if (rule !== null) return rule;
  const alert = asRecord(data["alert"]);
  const alertRule = alert === null ? null : asRecord(alert["rule"]);
  if (alertRule !== null) return alertRule;
  const output = asRecord(data["output"]);
  return output === null ? null : asRecord(output["rule"]);
}

export function extractRuleId(resp: unknown): string | null {
  const data = dataOf(resp);
  const rule = ruleRecordOf(data);
  if (rule !== null && rule["id"] != null) return String(rule["id"]);
  const out = data["output"];
  if (Array.isArray(out)) {
    for (const entry of out) {
      if (typeof entry !== "string") continue;
      const m = /^id:\s*'(\d+)'\s*$/.exec(entry.trim());
      if (m) return m[1]!;
    }
  }
  return null;
}

export function isAlert(resp: unknown): boolean {
  const data = dataOf(resp);
  const alert = data["alert"];
  if (alert === true) return true;
  const alertRec = asRecord(alert);
  if (alertRec !== null && ruleRecordOf(alertRec) !== null) return true;
  const out = data["output"];
  if (Array.isArray(out)) {
    return out.some((l) => typeof l === "string" && l.includes("**Alert to be generated."));
  }
  return false;
}

export function extractToken(resp: unknown): string | null {
  const t = dataOf(resp)["token"];
  return typeof t === "string" && t.length > 0 ? t : null;
}

// ---------------------------------------------------------------------------
// transport (node http/https, self-signed lab CAs allowed — same as upstream)
// ---------------------------------------------------------------------------

interface HttpReply {
  status: number;
  body: string;
}

function requestRaw(
  url: string,
  method: string,
  headers: Record<string, string>,
  body: string | null,
): Promise<HttpReply> {
  return new Promise<HttpReply>((resolve, reject) => {
    const u = new URL(url);
    const collect = (res: IncomingMessage): void => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => {
        data += chunk;
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }));
    };
    const req =
      u.protocol === "https:"
        ? httpsRequest(u, { method, headers, rejectUnauthorized: false }, collect)
        : httpRequest(u, { method, headers }, collect);
    req.on("error", reject);
    req.setTimeout(15_000, () => req.destroy(new Error("request timeout")));
    if (body !== null) req.write(body);
    req.end();
  });
}

async function login(api: string, user: string, pass: string): Promise<string> {
  const basic = Buffer.from(`${user}:${pass}`, "utf8").toString("base64");
  const reply = await requestRaw(
    `${api}/security/user/authenticate?raw=true`,
    "POST",
    { Authorization: `Basic ${basic}` },
    null,
  );
  const token = reply.body.trim();
  if (reply.status !== 200 || token.length === 0 || token.startsWith("{")) {
    throw new Error(`API login failed (HTTP ${reply.status}): ${reply.body.slice(0, 200)}`);
  }
  return token;
}

async function putLog(
  api: string,
  jwt: string,
  log: string,
  sessionToken: string | null,
): Promise<unknown> {
  // wazuh 4.14 LogtestRequest schema: {event, log_format, location, token?}
  // (same shape as the pinned SBoB repo's scripts/logtest-api.ts — the old
  // {log} payload is rejected with HTTP 400 "RequestBody is required").
  // The captured windows are auditd syslog-format lines, so log_format is
  // "syslog" like the recorded php corpora.
  const payload =
    sessionToken === null
      ? { event: log, log_format: "syslog", location: "sbob-php2shell-live" }
      : { event: log, log_format: "syslog", location: "sbob-php2shell-live", token: sessionToken };
  // explicit Content-Length (SBoB PR #45): node otherwise sends
  // Transfer-Encoding: chunked on a reused keep-alive socket, which the
  // 4.14 API rejects with HTTP 400 "RequestBody is required"
  const body = JSON.stringify(payload);
  const reply = await requestRaw(
    `${api}/logtest`,
    "PUT",
    { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json", "Content-Length": String(body.length) },
    body,
  );
  if (reply.status !== 200) {
    throw new Error(`PUT /logtest failed (HTTP ${reply.status}): ${reply.body.slice(0, 200)}`);
  }
  return JSON.parse(reply.body);
}

async function closeSession(api: string, jwt: string, sessionToken: string): Promise<void> {
  await requestRaw(
    `${api}/logtest/sessions/${sessionToken}`,
    "DELETE",
    { Authorization: `Bearer ${jwt}` },
    null,
  );
}

// ---------------------------------------------------------------------------
// replay
// ---------------------------------------------------------------------------

export interface ReplayResult {
  ruleIds: string[];
  alertRuleIds: string[];
  lineCount: number;
  sessionToken: string | null;
}

export async function replayCorpus(
  api: string,
  jwt: string,
  lines: readonly string[],
): Promise<ReplayResult> {
  let token: string | null = null;
  const ruleIds: string[] = [];
  const alertRuleIds: string[] = [];
  for (const log of lines) {
    const resp = await putLog(api, jwt, log, token);
    const t = extractToken(resp);
    if (t !== null) token = t;
    const id = extractRuleId(resp);
    if (id !== null) ruleIds.push(id);
    if (isAlert(resp) && id !== null) alertRuleIds.push(id);
  }
  return { ruleIds, alertRuleIds, lineCount: lines.length, sessionToken: token };
}

export function repeatLines(lines: readonly string[], repeats: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < repeats; i++) out.push(...lines);
  return out;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

interface CliConfig {
  api: string;
  user: string;
  pass: string;
  file: string;
  mode: "benign" | "drift";
  expect: string[];
  expectAbsent: string[];
  expectSustained: string[];
  repeats: number;
}

function parseArgs(argv: readonly string[]): CliConfig | null {
  const c: Partial<CliConfig> = { user: "wazuh", expect: [], expectAbsent: [], expectSustained: [], repeats: 8 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const next = (): string => {
      if (i + 1 >= argv.length) {
        throw new Error(`missing value for ${a}`);
      }
      return argv[++i]!;
    };
    if (a === "--api") c.api = next();
    else if (a === "--user") c.user = next();
    else if (a === "--pass") c.pass = next();
    else if (a === "--file") c.file = next();
    else if (a === "--mode") {
      const m = next();
      if (m !== "benign" && m !== "drift") throw new Error(`--mode must be benign|drift (got ${m})`);
      c.mode = m;
    } else if (a === "--expect") c.expect = next().split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--expect-absent")
      c.expectAbsent = next().split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--expect-sustained")
      c.expectSustained = next().split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--repeats") {
      const n = Number(next());
      if (!Number.isInteger(n) || n < 1) throw new Error("--repeats requires an integer >= 1");
      c.repeats = n;
    } else {
      throw new Error(`unknown option ${a}`);
    }
  }
  // environment fallbacks — the same contract as the pinned SBoB repo's
  // scripts/logtest-api.ts (SBOB_WAZUH_API_USER / SBOB_WAZUH_API_PASS)
  c.api = c.api || process.env["SBOB_WAZUH_API_URL"];
  c.user = c.user || process.env["SBOB_WAZUH_API_USER"] || "wazuh";
  c.pass = c.pass ?? process.env["SBOB_WAZUH_API_PASS"];
  if (!c.api || !/^https?:\/\//.test(c.api)) throw new Error("--api <http(s) URL> is required");
  if (!c.file) throw new Error("--file <capture window> is required");
  if (c.mode !== "benign" && c.mode !== "drift") throw new Error("--mode benign|drift is required");
  if (c.mode === "drift" && c.expect!.length === 0)
    throw new Error("drift mode requires --expect <rule ids>");
  if (!c.pass) throw new Error("--pass (or SBOB_WAZUH_API_PASS) is required");
  return c as CliConfig;
}

async function main(): Promise<number> {
  let cfg: CliConfig;
  try {
    cfg = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(`usage error: ${e instanceof Error ? e.message : String(e)}`);
    console.error(
      "usage: node logtest-replay.ts --api https://host:55000 --pass <secret> --file <window.audit> \\" +
        "\n       --mode benign|drift [--expect 100111,...] [--expect-absent 100111,...] [--expect-sustained 100112,...] [--repeats 8]",
    );
    return 2;
  }

  const lines = corpusLines(readFileSync(cfg.file, "utf8"));
  if (lines.length === 0) {
    if (cfg.mode === "benign") {
      // the honest node-side-observer shape (delta 7): the exe-scoped keys
      // cannot tag the containerized workload, so the benign declared
      // behavior produces no sbob-tagged events. Nothing to replay, nothing
      // can fire; benign silence on tagged content is proven by the
      // recorded corpus (leg 1, scripts/logtest-api.ts --target php).
      console.log(
        `OK (vacuous): ${cfg.file} carries no sbob-tagged events (node-side observer mode, delta 7) — ` +
          "nothing can fire; benign silence on tagged content is proven by the recorded corpus (leg 1)",
      );
      return 0;
    }
    console.error(`FAIL: ${cfg.file} contains no event lines`);
    return 1;
  }
  console.log(`== [${cfg.file}] ${cfg.mode} mode: ${lines.length} event lines ==`);

  let jwt: string;
  try {
    jwt = await login(cfg.api, cfg.user, cfg.pass);
  } catch (e) {
    console.error(`ERROR: Wazuh API login failed — ${e instanceof Error ? e.message : String(e)}`);
    return 2;
  }

  const cleanSession = async (r: ReplayResult): Promise<void> => {
    try {
      if (r.sessionToken !== null) await closeSession(cfg.api, jwt, r.sessionToken);
    } catch {
      /* session_timeout closes it anyway */
    }
  };

  if (cfg.mode === "benign") {
    // one session, repeats passes: no drift alert, and the sustained
    // children can never fire because benign lines match no drift rule
    const res = await replayCorpus(cfg.api, jwt, repeatLines(lines, cfg.repeats));
    await cleanSession(res);
    const uniqueAlerts = [...new Set(res.alertRuleIds)];
    if (res.alertRuleIds.length > 0) {
      console.error(
        `FAIL: benign telemetry generated alerts (${uniqueAlerts.join(", ")}) — the capture window contains drift`,
      );
      console.error(`      all matched rule ids: ${[...new Set(res.ruleIds)].join(", ")}`);
      return 1;
    }
    console.log(
      `OK: benign telemetry silent across ${cfg.repeats} passes (${res.lineCount} lines/session, ` +
        `base-chain matches: ${[...new Set(res.ruleIds)].join(", ") || "none"})`,
    );
    return 0;
  }

  // drift mode: single pass — every mapped rule id must fire
  const single = await replayCorpus(cfg.api, jwt, lines);
  await cleanSession(single);
  const seen = new Set(single.ruleIds);
  const missing = cfg.expect.filter((id) => !seen.has(id));
  if (missing.length > 0) {
    console.error(`FAIL: drift telemetry did not fire: ${missing.join(", ")}`);
    console.error(`      fired during replay: ${[...seen].join(", ") || "(none)"}`);
    return 1;
  }
  for (const id of cfg.expect) console.log(`OK: rule ${id} fired on live telemetry`);

  // the recorded gap: rule ids that MUST NOT fire on this live window
  // (delta 7: exe-scoped rules cannot tag the containerized workload
  // node-side; their legs are proven on the recorded corpus, leg 1)
  const firedAbsent = cfg.expectAbsent.filter((id) => seen.has(id));
  if (firedAbsent.length > 0) {
    console.error(
      `FAIL: rules ${firedAbsent.join(", ")} fired although --expect-absent (they must stay untagged in this observer mode)`,
    );
    return 1;
  }
  for (const id of cfg.expectAbsent)
    console.log(`OK: rule ${id} correctly absent from this live window (delta 7 shape)`);

  // sustained pass: repeats passes in ONE session -> frequency children fire
  if (cfg.expectSustained.length > 0) {
    console.log(
      `== sustained check: ${cfg.repeats} passes in one session, expecting ` +
        `${cfg.expectSustained.join(" ")} ==`,
    );
    const sustained = await replayCorpus(cfg.api, jwt, repeatLines(lines, cfg.repeats));
    await cleanSession(sustained);
    const seenS = new Set(sustained.ruleIds);
    const missingS = cfg.expectSustained.filter((id) => !seenS.has(id));
    if (missingS.length > 0) {
      console.error(`FAIL: sustained rules did not fire after ${cfg.repeats} passes: ${missingS.join(", ")}`);
      console.error(`      fired during sustained replay: ${[...seenS].join(", ") || "(none)"}`);
      return 1;
    }
    for (const id of cfg.expectSustained) console.log(`OK: sustained rule ${id} fired on live telemetry`);
  }

  console.log(`PASS: live telemetry detection proven (${cfg.file})`);
  return 0;
}

// run only when executed directly (node logtest-replay.ts); imports stay inert
if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}
