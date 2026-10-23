# 🛡️ Nexus Dependency Fitness

**Factual dependency fitness attestation for your CI** — GHSA/CVE advisories (OSV), SPDX license risk, freshness, CycloneDX SBOM, and a deterministic 0–100 score, delivered as an **EIP-712 signed attestation with Merkle-anchored public proofs**.

> **legal_weight: 0** — this action reports verifiable facts only. It is not legal advice and makes no legal claims.

## Why

Standard dependency scanners drown you in alerts — most of which are unreachable in your code path. Nexus reports a **signed, independently verifiable** factual snapshot instead:

- ✅ **Deterministic score 0–100** — fixed formula (`100 − 25·critical − 15·high − 15·license_risk − 10·stale`), worst-case across batches. Same input → same score, every time.
- ✅ **Signed attestation** — EIP-712 signature by ERC-8004 agent **#636**, Merkle-anchored on Polygon. Anyone can verify without an account: `curl "<proof-url>"`.
- ✅ **SBOM included** — CycloneDX 1.5 on every run (EU CRA / US EO 14028 friendly).
- ✅ **Cheap & machine-native** — $0.05 per 25-package call, paid via prepaid credits (x402/USDC). No accounts, no seats, no sales calls.
- ✅ **SARIF output** — results land in your repo's **Security tab** via `upload-sarif`.

## Quick start

```yaml
name: Dependency Fitness
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1" # weekly Monday 06:00 UTC

permissions:
  contents: read

jobs:
  fitness:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v5
      - uses: rakhmadaa-gif/nexus-fitness-action@v1
        with:
          client-id: ${{ secrets.NEXUS_CLIENT_ID }}
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nexus-fitness.sarif
```

**One-time top-up** (from your laptop, not in CI):

```bash
npx nexus-gateway-sdk@2 topup --amount 5 --client-id my-org-ci
# 1 USDC = 100 CRED · fitness scan = 5 CRED ($0.05) per 25 packages
```

`client-id` is a **non-secret identifier** — anyone who knows it can only *add* credits, never spend yours.

## What gets scanned

Auto-detected from your repo (or pass `lockfile:` explicitly):

| Ecosystem | Lockfile / manifest |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `package.json` |
| Python | `requirements.txt`, `Pipfile.lock` |
| Go | `go.mod` |
| Rust | `Cargo.lock` |

Dev-only dependencies are excluded by default (`include-dev: true` to include). The scan set is capped at 250 packages (deterministic order) — honest reporting tells you when the cap or your spend ceiling truncated the scan.

## Inputs

| Input | Default | Description |
|---|---|---|
| `client-id` | — | **Required.** Non-secret Nexus client identifier for your CI. |
| `lockfile` | auto | Path (or comma-separated paths) to lockfile(s). Empty = auto-detect. |
| `repo` | `github.repository` | `owner/name` for freshness + stars metadata. |
| `max-spend` | `0.50` | Spend ceiling in USDC ($0.05 per 25-package call). |
| `fail-on` | `critical` | Fail the job when: `never` \| `critical` \| `high` \| `low` \| `score`. |
| `fail-on-license` | `false` | Fail when any scanned runtime dep carries a risky SPDX license (GPL/AGPL/SSPL/BUSL class). |
| `include-dev` | `false` | Include dev-only dependencies. |
| `skip-badge` | `false` | Skip the dynamic README badge suggestion. |

## Outputs

| Output | Description |
|---|---|
| `score` | Worst-case deterministic score 0–100 across scanned batches. |
| `critical-count` / `high-count` / `total-advisories` | Advisory counts. |
| `attestation-urls` | Newline-separated zero-trust proof URLs (one per batch). |
| `sarif-path` | SARIF file path for `upload-sarif`. |
| `cache-hit` | `true` when results came from the 6-hour cache (0 credits charged). |

## Verifying a proof (zero-trust)

Every run emits public proof URLs. No account, no login — the proof package contains the EIP-712 signature, Merkle proof, and on-chain anchor transaction:

```bash
curl -s "https://nexus-m2m-gateway.rakhadadaa.workers.dev/attestations/proof?hash=<struct_hash>" | jq
```

Verification chain: recover the signer from the EIP-712 signature → signer must own ERC-8004 identity **#636** on Polygon → the attestation's hash must be included in the Merkle root anchored on-chain. Full verifier script: [`nexus-gateway-sdk`](https://www.npmjs.com/package/nexus-gateway-sdk) → `verify` command.

## Pricing

| Item | Cost |
|---|---|
| Fitness attestation | **$0.05 per 25 packages** (5 CRED) |
| Cache hit (≤6h) | $0.00 — speed, not a discount |
| Top-up | `npx nexus-gateway-sdk@2 topup --amount 5 --client-id <id>` (USDC on Polygon/Base, 1 USDC = 100 CRED) |

Spend is bounded by `max-spend` (default $0.50/run). Batches beyond the ceiling are skipped and reported honestly in the job summary.

## Privacy

Your lockfile is parsed **inside your CI runner**. Only `name`, `version`, `ecosystem` tuples are sent to the attestation endpoint. No source code, no tokens, no repo contents.

## License compliance

License risk is computed **client-side in your runner** from public package registries (npm / PyPI / crates.io) and is **not part of the signed attestation** — the job summary labels it accordingly. The signed attestation covers advisories, freshness, SBOM, and score.

## License

MIT © rakhmadaa-gif — a [Nexus](https://github.com/rakhmadaa-gif) M2M service. Engine: `nexus-core-gateway` (EVM Sentinel v5.17.0-frontier).
