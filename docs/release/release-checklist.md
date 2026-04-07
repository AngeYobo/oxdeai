# OxDeAI v1.0.2 Release Checklist

## Status

Non-normative (developer documentation)






Use this checklist for protocol-grade releases in the `1.0.x` line.

## 1) API Extractor Baseline Update

Run:

```bash
pnpm -C packages/core api:report
pnpm -C packages/core api:check
```

If `api:check` reports signature drift and the change is intentional:

```bash
cp packages/core/temp/core.api.md packages/core/etc/core.api.md
pnpm -C packages/core api:check
```

Then commit baseline updates with rationale in PR notes.

## 2) Conformance Vector Update Rules

Rules:

- Vectors are frozen per protocol version.
- Do not regenerate vectors for the same version unless fixing an incorrect vector.
- Behavior-changing outputs require a new version baseline.

Commands:

```bash
pnpm -C packages/conformance extract
pnpm -C packages/conformance validate
```

Expected success line:

```text
Conformance passed: <N> assertions
```

## 3) Version Bump (Workspace)

For a coordinated patch bump:

1. Update versions in:
   - `packages/core/package.json`
   - `packages/sdk/package.json`
   - `packages/conformance/package.json`
2. Keep workspace pins for local monorepo development where intended.
3. Refresh lockfile:

```bash
pnpm install --no-frozen-lockfile
```

4. Update changelog entries before tagging.

## 4) Determinism + Invariant Test Gates

Run full quality gates:

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm test
pnpm -C packages/core api:check
pnpm -C packages/core api:fingerprint:check
pnpm -C packages/conformance validate
```

All commands MUST pass before release tag/publish.

## 5) End-to-End Envelope Generation + Verification

Example using CLI (from repo root):

```bash
# create a valid initial state file first (example path shown)
pnpm -C packages/cli start -- init --file /tmp/oxdeai-policy.json --json
pnpm -C packages/cli start -- launch PROVISION 320 us-east-1 --agent agent-1 --nonce 1 --json

# build artifacts
pnpm -C packages/cli start -- build --state .oxdeai/state.json --out .oxdeai/snapshot.bin --json
pnpm -C packages/cli start -- make-envelope --out .oxdeai/envelope.bin --json

# verify snapshot/audit/envelope
pnpm -C packages/cli start -- verify --kind snapshot --file .oxdeai/snapshot.bin --json
pnpm -C packages/cli start -- verify --kind audit --file .oxdeai/audit.ndjson --mode strict --json
pnpm -C packages/cli start -- verify --kind envelope --file .oxdeai/envelope.bin --mode strict --json
```

Notes:

- Strict mode may return `inconclusive` without `STATE_CHECKPOINT`.
- Best-effort mode can be used for diagnostics.

## 6) Security Notes

- v1.0.2 authorization verification in the reference profile uses shared-secret/HMAC.
- Signing secrets MUST be managed in secure storage (KMS/HSM preferred).
- Do not commit secrets, OTPs, or private key material.
- Use environment-specific key isolation and rotation procedures.
- Follow coordinated disclosure guidance in `SECURITY.md`.

## 7) Tag + Publish Order

After all gates pass:

```bash
git tag vX.Y.Z
git push origin main --tags
```

Publish in dependency order:

1. `@oxdeai/core`
2. `@oxdeai/sdk`
3. `@oxdeai/conformance`

Verify on npm:

```bash
npm view @oxdeai/core version --registry=https://registry.npmjs.org
npm view @oxdeai/sdk version --registry=https://registry.npmjs.org
npm view @oxdeai/conformance version --registry=https://registry.npmjs.org
```
