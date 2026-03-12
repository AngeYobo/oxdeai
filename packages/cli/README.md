# @oxdeai/cli

Protocol-oriented command-line tooling for OxDeAI.

`@oxdeai/cli` is a thin Node.js wrapper around `@oxdeai/core` verification and local state workflows. It is framework-agnostic and intended for local policy operations, artifact inspection, and deterministic verification.

## Quickstart

### End users

Install the CLI:

```bash
npm install -g @oxdeai/cli
```

Basic commands:

```bash
oxdeai --help
oxdeai --version
oxdeai verify snap
oxdeai verify envelope
oxdeai build snapshot
oxdeai verify all
oxdeai inspect snapshot --file .oxdeai/snapshot.bin
oxdeai doctor
```

### Local monorepo contributors

Build the package from the repo root:

```bash
pnpm -C packages/cli build
```

Run the CLI from the monorepo root:

```bash
pnpm oxdeai --help
pnpm oxdeai --version
pnpm oxdeai verify snap --file packages/cli/.oxdeai/snapshot.bin --json
```

Run it from inside `packages/cli`:

```bash
pnpm build
node dist/main.js --help
node dist/main.js verify snap --file .oxdeai/snapshot.bin --json
```

For a local global-style workflow:

```bash
cd packages/cli
npm link
oxdeai --help
```

## Command Surface

- `oxdeai build`
- `oxdeai verify`
- `oxdeai inspect`
- `oxdeai doctor`
- `oxdeai paths`
- `oxdeai auth`
- `oxdeai examples`
- `oxdeai replay`

Legacy helper commands are still available (`init`, `launch`, `state`, `audit`, `verify-audit`, `make-envelope`, `verify-envelope`, `snapshot-hash`) for local development workflows.

## Core Commands

### build

Builds a canonical snapshot verification payload from state.

```bash
oxdeai build snapshot
oxdeai build --state .oxdeai/state.json --out .oxdeai/snapshot.bin --json
```

### verify

Verifies one artifact kind at a time:

- `snapshot`
- `audit`
- `envelope`
- `authorization`

Examples:

```bash
oxdeai verify snap
oxdeai verify audit
oxdeai verify envelope
oxdeai verify auth --file authorization.json --expected-issuer oxdeai://issuer --expected-audience rp://tool-gateway --json
oxdeai verify --kind snapshot --file snapshot.bin --json
oxdeai verify --kind audit --file audit.ndjson --mode strict --json
oxdeai verify --kind envelope --file envelope.bin --trusted-keyset keyset.json --require-signature --json
oxdeai verify --kind authorization --file authorization.json --expected-issuer oxdeai://issuer --expected-audience rp://tool-gateway --json
```

`verify auth` does not assume a default file. Pass `--file <authorization.json>` explicitly.

### inspect

Inspects local protocol artifacts without changing them.

```bash
oxdeai inspect snapshot --file .oxdeai/snapshot.bin
oxdeai inspect audit --file .oxdeai/audit.ndjson
oxdeai inspect envelope --file .oxdeai/envelope.bin
oxdeai inspect auth --file authorization.json
```

### verify all

Runs snapshot, audit, and envelope verification together using local defaults.

```bash
oxdeai verify all
```

### auth

Creates and inspects authorization artifacts for local relying-party tests.

```bash
oxdeai auth create PROVISION 100 us-east-1 --agent agent-1 --nonce 1 --out authorization.json --json
oxdeai auth inspect --file authorization.json
```

### doctor and paths

Shows local path defaults and checks whether expected files exist.

```bash
oxdeai paths
oxdeai doctor
```

### examples init

Writes a starter local state file and clears the audit log.

```bash
oxdeai examples init
```

### launch dry-run

Evaluates an action without mutating local state or audit files.

```bash
oxdeai launch dry-run PROVISION 100 us-east-1 --agent agent-1 --nonce 1 --json
```

### replay

Protocol-aware stub in `0.1.x`. It returns a clear unsupported response and points users to deterministic audit verification (`verify --kind audit`).

## Output and Exit Codes

- Human-readable output by default
- Machine-readable output with `--json`

Exit codes:

- `0` = verification `ok` / command success
- `1` = verification `invalid` or malformed input/runtime failure
- `2` = usage/flag parsing error
- `3` = verification `inconclusive`

## Troubleshooting

- If `oxdeai: command not found`, the package is not installed or linked globally yet. Use `npm install -g @oxdeai/cli` or `npm link` from `packages/cli`.
- In the monorepo, prefer `pnpm oxdeai ...` from the repo root or `node dist/main.js ...` from `packages/cli`. `pnpm exec oxdeai` is not the primary local workflow here.
- Default local file paths are `.oxdeai/state.json` and `.oxdeai/audit.ndjson`. Pass `--state`, `--audit`, `--file`, or `--out` explicitly if you are working outside that layout.

## PDP / PEP Boundary

The CLI does not replace a runtime PEP. It is intended for deterministic protocol artifact handling, validation, and local operational tooling around the OxDeAI PDP/PEP model.
