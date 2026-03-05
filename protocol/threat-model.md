# OxDeAI Threat Model

This document captures the protocol threat model for OxDeAI.

Reference:
- Primary protocol spec: [protocol.md](./protocol.md)
- Supporting spec notes: [spec.md](./spec.md)

## Covered Risks
- Replay abuse
- Runaway execution/tool loops
- Concurrency explosion
- Silent budget drain
- Recursive planning escalation

## Security Goals
- Deterministic, fail-closed policy decisions
- Pre-execution economic containment
- Tamper-evident audit chain
- Verifiable protocol artifacts

## Out of Scope
- Business logic correctness of downstream systems
- Key custody / wallet infrastructure
- Host runtime compromise
