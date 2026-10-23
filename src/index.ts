/**
 * Nexus Dependency Fitness — GitHub Action main.
 * Factual dependency fitness attestation via nexus-gateway-sdk v2.
 * legal_weight: 0 — facts only, not legal advice.
 */

import * as core from "@actions/core";
import * as cache from "@actions/cache";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  parseLockfile,
  preparePackages,
  mergePackageLists,
  sortPackagesDeterministic,
  capPackages,
  toFitnessPayload,
  attestFitnessBatched,
  NexusError,
  PACKAGES_MAX,
  FITNESS_DEFAULT_BASE_URL,
  type FitnessPackageInput,
  type ResolvedPackage,
  type MergedFitnessResult,
} from "nexus-gateway-sdk";

const WORKER_BASE = "https://nexus-m2m-gateway.rakhadadaa.workers.dev";
const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const ANNOTATION_CAP = 10;
const LICENSE_LOOKUP_CONCURRENCY = 5;
const LICENSE_LOOKUP_TIMEOUT_MS = 8000;

// Mirror of gateway RISKY_LICENSES (engine index.ts, SPDX incl. deprecated forms).
const RISKY_LICENSE_TOKENS = [
  "GPL-2.0-ONLY", "GPL-2.0-OR-LATER", "GPL-2.0",
  "GPL-3.0-ONLY", "GPL-3.0-OR-LATER", "GPL-3.0",
  "AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER", "AGPL-3.0", "AGPL-1.0",
  "LGPL-2.1-ONLY", "LGPL-2.1-OR-LATER", "LGPL-2.1",
  "LGPL-3.0-ONLY", "LGPL-3.0-OR-LATER", "LGPL-3.0",
  "SSPL-1.0", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0",
  "BUSL-1.1", "ELASTIC-2.0", "POLYFORM-SMALL-BUSINESS-1.0.0",
];

const AUTO_DETECT_ORDER = [
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "requirements.txt",
  "Pipfile.lock",
  "go.mod",
  "Cargo.lock",
];

interface LicenseRow {
  package: string;
  ecosystem: string;
  license: string;
  risky: boolean;
}

function isRiskyLicense(expr: string | null | undefined): boolean {
  if (!expr) return false;
  const alternatives = expr.toUpperCase().split(/\s+OR\s+/).map((a) => a.trim());
  if (alternatives.length === 0) return false;
  // Disjunctive license: safe if ANY alternative is not risky.
  return alternatives.every((alt) => RISKY_LICENSE_TOKENS.some((t) => alt.includes(t)));
}

async function lookupNpmLicense(name: string): Promise<string | null> {
  const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}/latest`, {
    signal: AbortSignal.timeout(LICENSE_LOOKUP_TIMEOUT_MS),
  });
  if (!res.ok) return null;
  const json = (await res.json()) as { license?: unknown };
  if (typeof json.license === "string") return json.license;
  if (json.license && typeof json.license === "object") {
    const l = json.license as { type?: string };
    return l.type ?? null;
  }
  return null;
}

async function lookupPypiLicense(name: string): Promise<string | null> {
  const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, {
    signal: AbortSignal.timeout(LICENSE_LOOKUP_TIMEOUT_MS),
  });
  if (!res.ok) return null;
  const json = (await res.json()) as { info?: { license_expression?: string; license?: string } };
  return json.info?.license_expression || json.info?.license || null;
}

async function lookupCratesLicense(name: string): Promise<string | null> {
  const res = await fetch(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`, {
    headers: { "User-Agent": "nexus-fitness-action (github.com/rakhmadaa-gif/nexus-fitness-action)" },
    signal: AbortSignal.timeout(LICENSE_LOOKUP_TIMEOUT_MS),
  });
  if (!res.ok) return null;
  const json = (await res.json()) as { crate?: { license?: string } };
  return json.crate?.license ?? null;
}

async function lookupLicenses(packages: FitnessPackageInput[]): Promise<LicenseRow[]> {
  const rows: LicenseRow[] = [];
  for (let i = 0; i < packages.length; i += LICENSE_LOOKUP_CONCURRENCY) {
    const slice = packages.slice(i, i + LICENSE_LOOKUP_CONCURRENCY);
    const settled = await Promise.allSettled(
      slice.map(async (p) => {
        let license: string | null = null;
        if (p.ecosystem === "npm") license = await lookupNpmLicense(p.name);
        else if (p.ecosystem === "PyPI") license = await lookupPypiLicense(p.name);
        else if (p.ecosystem === "crates.io") license = await lookupCratesLicense(p.name);
        else return { package: p.name, ecosystem: p.ecosystem, license: "unknown", risky: false } as LicenseRow;
        return {
          package: p.name,
          ecosystem: p.ecosystem,
          license: license ?? "unknown",
          risky: isRiskyLicense(license),
        } as LicenseRow;
      }),
    );
    for (const s of settled) {
      if (s.status === "fulfilled") rows.push(s.value);
    }
  }
  return rows;
}

/** Best-effort: find the line of a package entry in the primary lockfile. */
function findPackageLine(lockfilePath: string | null, pkgName: string): number {
  if (!lockfilePath) return 1;
  try {
    const content = fs.readFileSync(lockfilePath, "utf8");
    const lines = content.split("\n");
    const patterns = [
      `"node_modules/${pkgName}"`,
      `"${pkgName}"`,
      `${pkgName}@`,
      `name = "${pkgName}"`,
      `${pkgName}==`,
    ];
    for (const pat of patterns) {
      const idx = lines.findIndex((l) => l.includes(pat));
      if (idx >= 0) return idx + 1;
    }
  } catch {
    /* best-effort */
  }
  return 1;
}

async function probeBadge(clientId: string): Promise<string | null> {
  try {
    const res = await fetch(`${WORKER_BASE}/v1/badge?client_id=${encodeURIComponent(clientId)}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      const ct = res.headers.get("content-type") ?? "";
      if (ct.includes("image/svg")) return `${WORKER_BASE}/v1/badge?client_id=${encodeURIComponent(clientId)}`;
    }
  } catch {
    /* endpoint not live yet (gateway v5.18.0) — skip */
  }
  return null;
}

function severityRank(cls: string): number {
  const c = cls.toLowerCase();
  if (c === "critical") return 0;
  if (c === "high") return 1;
  if (c === "medium" || c === "moderate") return 2;
  return 3;
}

function severityLabel(adv: { severity_class: string; severity_label?: string | null }): string {
  return adv.severity_label ?? adv.severity_class;
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: string;
  uri: string;
  line: number;
}

function buildSarif(results: SarifResult[], ruleHelp: Record<string, string>): string {
  const rules = [...new Set(results.map((r) => r.ruleId))].map((id) => ({
    id,
    name: id,
    shortDescription: { text: id },
    helpUri: ruleHelp[id] ?? "https://nexus-m2m-gateway.rakhadadaa.workers.dev/llms.txt",
  }));
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Nexus Dependency Fitness",
              version: "1.0.0",
              informationUri: "https://github.com/rakhmadaa-gif/nexus-fitness-action",
              rules,
            },
          },
          results: results.map((r) => ({
            ruleId: r.ruleId,
            level: r.level,
            message: { text: r.message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: r.uri },
                  region: { startLine: r.line },
                },
              },
            ],
          })),
        },
      ],
    },
    null,
    2,
  );
}

async function run(): Promise<void> {
  const clientId = core.getInput("client-id", { required: true });
  const lockfileInput = core.getInput("lockfile").trim();
  const repo = core.getInput("repo").trim() || process.env.GITHUB_REPOSITORY || "";
  const maxSpend = parseFloat(core.getInput("max-spend") || "0.50");
  const failOn = core.getInput("fail-on") || "critical";
  const failOnLicense = core.getInput("fail-on-license") === "true";
  const includeDev = core.getInput("include-dev") === "true";
  const skipBadge = core.getInput("skip-badge") === "true";

  const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd();

  // -- 1. resolve lockfiles ------------------------------------------------------
  let lockfilePaths: string[] = [];
  if (lockfileInput) {
    lockfilePaths = lockfileInput.split(",").map((p) => p.trim()).filter(Boolean).map((p) => path.resolve(workspace, p));
    for (const p of lockfilePaths) {
      if (!fs.existsSync(p)) throw new Error(`Lockfile not found: ${p}`);
    }
  } else {
    for (const name of AUTO_DETECT_ORDER) {
      const p = path.join(workspace, name);
      if (fs.existsSync(p)) {
        lockfilePaths = [p];
        break;
      }
    }
    if (lockfilePaths.length === 0) {
      core.info("No lockfile detected — scanning repo metadata only (repo mode).");
    }
  }
  const primaryLockfile = lockfilePaths[0] ?? null;

  // -- 2. parse + merge ----------------------------------------------------------
  let packages: ResolvedPackage[] = [];
  for (const p of lockfilePaths) {
    const parsed = parseLockfile(p, fs.readFileSync(p, "utf8"));
    core.info(`Parsed ${path.basename(p)}: ${parsed.packages.length} packages (${parsed.format}).`);
    packages = mergePackageLists(packages, parsed.packages).packages;
  }
  if (includeDev) {
    packages = capPackages(sortPackagesDeterministic(packages), PACKAGES_MAX).packages;
  } else {
    packages = preparePackages(packages, PACKAGES_MAX).packages;
  }
  core.info(`Scan set: ${packages.length} runtime packages (cap 250).`);
  const fitnessInput: FitnessPackageInput[] = toFitnessPayload(packages);

  // -- 3. cache (6h TTL, best-effort) ---------------------------------------------
  const cacheKeyPayload = JSON.stringify({ repo, includeDev, packages: fitnessInput });
  const cacheKey = `nexus-fitness-v1-${createHash("sha256").update(cacheKeyPayload).digest("hex").slice(0, 32)}`;
  let merged: MergedFitnessResult | null = null;
  let cacheHit = false;
  const cacheFile = path.join(process.env.RUNNER_TEMP ?? workspace, "nexus-fitness-cache.json");
  try {
    if (await cache.restoreCache([cacheFile], cacheKey)) {
      const raw = JSON.parse(fs.readFileSync(cacheFile, "utf8")) as { saved_at: number; merged: MergedFitnessResult };
      if (Date.now() - raw.saved_at < CACHE_TTL_MS) {
        merged = raw.merged;
        cacheHit = true;
        core.info(`Cache hit (${cacheKey}) — reusing attestation from <6h ago.`);
      } else {
        core.info("Cache found but older than 6h — rescanning.");
      }
    }
  } catch (e) {
    core.info(`Cache unavailable (${(e as Error).message}) — continuing without cache.`);
  }

  // -- 4. attestation -------------------------------------------------------------
  if (!merged) {
    merged = await attestFitnessBatched({
      clientId,
      packages: fitnessInput,
      repo: repo || undefined,
      maxSpendUsdc: Number.isFinite(maxSpend) ? maxSpend : undefined,
      onBatch: (info) =>
        core.info(`Batch ${info.batchIndex + 1}/${info.totalBatches}: score ${info.response.data.score}, ${info.response.data.facts.advisory_counts.total} advisories.`),
    });
    try {
      fs.writeFileSync(cacheFile, JSON.stringify({ saved_at: Date.now(), merged }));
      await cache.saveCache([cacheFile], cacheKey);
      core.info(`Saved cache ${cacheKey}.`);
    } catch (e) {
      core.info(`Cache save skipped (${(e as Error).message}).`);
    }
  }

  // -- 5. outputs ------------------------------------------------------------------
  core.setOutput("score", String(merged.score));
  core.setOutput("critical-count", String(merged.critical_count));
  core.setOutput("high-count", String(merged.high_count));
  core.setOutput("total-advisories", String(merged.total_advisories));
  core.setOutput("attestation-urls", merged.proof_urls.join("\n"));
  core.setOutput("cache-hit", cacheHit ? "true" : "false");

  // -- 6. license lookup (client-side, not part of signed attestation) --------------
  const scannedPackages = packages.slice(0, merged.batches.length * 25);
  const licenseRows = await lookupLicenses(scannedPackages);
  const riskyLicenses = licenseRows.filter((r) => r.risky);

  // -- 7. SARIF ---------------------------------------------------------------------
  const advisories = [...merged.advisories].sort((a, b) => severityRank(a.severity_class) - severityRank(b.severity_class));
  const sarifResults: SarifResult[] = [];
  const ruleHelp: Record<string, string> = {};
  const baseUri = primaryLockfile ? path.relative(workspace, primaryLockfile) : "package.json";
  for (const adv of advisories) {
    sarifResults.push({
      ruleId: adv.id,
      level: adv.severity_class.toLowerCase() === "critical" ? "error" : adv.severity_class.toLowerCase() === "high" ? "warning" : "note",
      message: `${adv.package}: ${adv.summary} (severity ${severityLabel(adv)})`,
      uri: baseUri,
      line: findPackageLine(primaryLockfile, adv.package),
    });
    ruleHelp[adv.id] = adv.url;
  }
  for (const row of riskyLicenses) {
    sarifResults.push({
      ruleId: "nexus/license-risk",
      level: "error",
      message: `${row.package}: risky SPDX license "${row.license}" (${row.ecosystem}) — client-side registry lookup, not part of the signed attestation.`,
      uri: baseUri,
      line: findPackageLine(primaryLockfile, row.package),
    });
  }
  const sarifPath = path.join(workspace, "nexus-fitness.sarif");
  fs.writeFileSync(sarifPath, buildSarif(sarifResults, ruleHelp));
  core.setOutput("sarif-path", sarifPath);

  // -- 8. annotations (≤10) ----------------------------------------------------------
  let annotated = 0;
  for (const adv of advisories) {
    if (annotated >= ANNOTATION_CAP) break;
    const text = `[${adv.id}] ${adv.package}: ${adv.summary} (${adv.url})`;
    if (adv.severity_class.toLowerCase() === "critical") {
      core.error(text, { file: baseUri, startLine: findPackageLine(primaryLockfile, adv.package) });
      annotated++;
    } else if (adv.severity_class.toLowerCase() === "high") {
      core.warning(text, { file: baseUri, startLine: findPackageLine(primaryLockfile, adv.package) });
      annotated++;
    }
  }

  // -- 9. job summary ------------------------------------------------------------------
  const badgeUrl = skipBadge ? null : await probeBadge(clientId);
  const scoreColor = merged.score >= 80 ? "🟢" : merged.score >= 50 ? "🟡" : "🔴";
  const lines: string[] = [];
  lines.push(`## 🛡️ Nexus Dependency Fitness ${scoreColor}`);
  lines.push("");
  lines.push(`**Score: ${merged.score}/100** — ${merged.critical_count} critical, ${merged.high_count} high, ${merged.total_advisories} total advisories.`);
  lines.push("");
  lines.push(`Factual attestation only (legal_weight: 0). Signed EIP-712 (ERC-8004 agent #636), Merkle-anchored on Polygon.`);
  lines.push("");
  if (merged.proof_urls.length > 0) {
    lines.push(`**Zero-trust proofs (verify independently, no account needed):**`);
    for (const u of merged.proof_urls) lines.push(`- ${u}`);
    lines.push("");
  }
  if (advisories.length > 0) {
    lines.push(`### Advisories`);
    lines.push("");
    lines.push(`| Severity | Package | Advisory | Published |`);
    lines.push(`|---|---|---|---|`);
    for (const adv of advisories.slice(0, 30)) {
      lines.push(`| ${severityLabel(adv)} | ${adv.package} | [${adv.id}](${adv.url}) | ${adv.published || "?"} |`);
    }
    if (advisories.length > 30) lines.push(`| ... | ${advisories.length - 30} more | | |`);
    lines.push("");
  } else {
    lines.push(`✅ No advisories found in scanned packages.`);
    lines.push("");
  }
  if (licenseRows.length > 0) {
    lines.push(`### Licenses (client-side registry lookup — not part of the signed attestation)`);
    lines.push("");
    lines.push(`| Package | License | Risk |`);
    lines.push(`|---|---|---|`);
    for (const row of licenseRows.slice(0, 40)) {
      lines.push(`| ${row.package} | ${row.license} | ${row.risky ? "⚠️ risky" : "ok"} |`);
    }
    if (licenseRows.length > 40) lines.push(`| ... | ${licenseRows.length - 40} more | |`);
    lines.push("");
  }
  if (merged.truncated) {
    lines.push(`⚠️ **Spend ceiling reached:** ${merged.unscanned_packages} packages were NOT scanned (max-spend $${maxSpend}). Raise \`max-spend\` to scan them.`);
    lines.push("");
  }
  if (cacheHit) lines.push(`♻️ Results served from 6-hour cache (0 credits charged this run).`);
  if (merged.credits_charged > 0) lines.push(`💰 Credits charged this run: ${merged.credits_charged} CRED ($${(merged.credits_charged / 100).toFixed(2)}).`);
  if (badgeUrl) {
    lines.push("");
    lines.push(`**README badge:**`);
    lines.push("");
    lines.push("```markdown");
    lines.push(`[![Nexus Fitness](${badgeUrl})](${merged.proof_urls[0] ?? `${WORKER_BASE}/`})`);
    lines.push("```");
  }
  if (merged.critical_count > 0 || merged.score < 50) {
    lines.push("");
    lines.push(`### 🔬 Go deeper (optional)`);
    lines.push("");
    lines.push(`Want the top-3 exploit scenarios with an immutable IPFS forensic bundle? Run from your laptop:`);
    lines.push("");
    lines.push("```bash");
    lines.push(`npx nexus-gateway-sdk@2 forensic --repo ${repo || "owner/name"} --client-id ${clientId}`);
    lines.push("```");
    lines.push("");
    lines.push(`($3.50 — top-3 detected exploit scenarios by severity, deterministic narrative, dual-pinned IPFS bundle, same signed-attestation guarantees.)`);
  }
  await core.summary.addRaw(lines.join("\n")).write();

  // -- 10. fail logic --------------------------------------------------------------------
  const failNow =
    (failOn === "critical" && merged.critical_count > 0) ||
    (failOn === "high" && (merged.critical_count > 0 || merged.high_count > 0)) ||
    (failOn === "low" && merged.total_advisories > 0) ||
    (failOn === "score" && merged.score < 50) ||
    (failOnLicense && riskyLicenses.length > 0);
  if (failNow) {
    const reasons: string[] = [];
    if (merged.critical_count > 0) reasons.push(`${merged.critical_count} critical advisories`);
    if (merged.high_count > 0) reasons.push(`${merged.high_count} high advisories`);
    if (failOn === "low" && merged.total_advisories > 0) reasons.push(`${merged.total_advisories} advisories`);
    if (merged.score < 50 && failOn === "score") reasons.push(`score ${merged.score} < 50`);
    if (failOnLicense && riskyLicenses.length > 0) reasons.push(`${riskyLicenses.length} risky licenses`);
    core.setFailed(`Nexus Dependency Fitness threshold exceeded: ${reasons.join(", ")}. See job summary for details and proof URLs.`);
  } else {
    core.info(`Done. Score ${merged.score}, ${merged.total_advisories} advisories, ${riskyLicenses.length} risky licenses.`);
  }
}

run().catch((err) => {
  if (err instanceof NexusError && err.statusCode === 402) {
    core.setFailed(`${err.message}\n\nSome batches may have been charged before the balance ran out. The client-id is a NON-secret CI identifier — anyone with it can only ADD credits, not spend yours.`);
  } else {
    core.setFailed(`Nexus Dependency Fitness action failed: ${(err as Error).message}`);
  }
});
