# Go Conformance Harness (Adapter Protocol)

This harness reads OxDeAI conformance vectors from `packages/conformance/vectors` and prints PASS/FAIL assertions similar to the TypeScript validator.

It is intended for Rust/Go/Python native implementations that want protocol-aligned validation without depending on the TypeScript runtime directly.

## Status

- Harness runner: implemented in Go (`main.go`)
- Adapter implementation: provided by you (any language) via a simple stdin/stdout JSON protocol

## Run

From `packages/conformance/go-harness`:

```bash
go run ./main.go --adapter-bin ./your-adapter --vectors ../vectors
```

You can pass adapter arguments with repeated `--adapter-arg`:

```bash
go run ./main.go --adapter-bin ./your-adapter --adapter-arg --mode --adapter-arg strict --vectors ../vectors
```

## Adapter Protocol

The harness sends one JSON request to the adapter process stdin and expects one JSON response on stdout.

### Request

```json
{
  "op": "intent_hash",
  "input": { "intent": { "...": "..." } }
}
```

### Response

```json
{
  "ok": true,
  "output": { "hash": "..." }
}
```

Error response:

```json
{
  "ok": false,
  "error": "explanation"
}
```

## Required `op` values

- `intent_hash`
- `evaluate_authorization`
- `encode_snapshot`
- `verify_snapshot`
- `canonical_json`
- `verify_authorization`
- `verify_audit_case`
- `verify_envelope_case`
- `verify_authorization_signature_case`
- `verify_envelope_signature_case`

## Output fields by operation

### `intent_hash`
- output: `{ "hash": "<hex>" }`

### `evaluate_authorization`
- output:
  - `authorization` object (must include at least `intent_hash`, `state_hash`, `expires_at`, `signature`)
  - `canonical_signing_payload` string

### `encode_snapshot`
- output:
  - `snapshot_base64`
  - `policy_id`

### `verify_snapshot`
- output:
  - `status`
  - `stateHash`
  - `policyId` (optional)
  - `violations`

### `verify_authorization` / `verify_audit_case` / `verify_envelope_case` / signature-case ops
- output:
  - `status`
  - `violations`
  - optional: `policyId`, `stateHash`, `auditHeadHash` when relevant

## Notes

- The harness itself does not redefine protocol semantics.
- Vectors remain the behavioral truth source.
- A native implementation is considered aligned when it reproduces expected vector outcomes.
