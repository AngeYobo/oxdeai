# Contributing to OxDeAI

## Project Philosophy

OxDeAI is a deterministic authorization protocol for autonomous systems. The project is intentionally small, verifiable, and framework-agnostic.

Contributions should preserve:

- deterministic behavior
- fail-closed enforcement
- clear protocol boundaries
- independent verifiability

## Repository Structure

- `@oxdeai/core` (`packages/core`): protocol reference implementation
- `@oxdeai/sdk` (`packages/sdk`): integration surface for embedding OxDeAI in runtimes
- `@oxdeai/conformance` (`packages/conformance`): protocol vectors and validation runner
- `@oxdeai/cli` (`packages/cli`): protocol tooling for local build/verify/replay workflows
- `examples/*`: reference and framework integration demonstrations

## Contribution Areas

Common contribution categories:

- runtime adapters
- SDK improvements
- conformance vectors and validation coverage
- protocol and integration documentation
- examples and demo hardening
- CLI/tooling improvements

## Pull Request Workflow

1. Fork the repository.
2. Create a feature branch from `main`.
3. Implement the change with focused commits.
4. Run validation before opening a PR:
   - `pnpm build`
   - `pnpm test`
   - `pnpm -C packages/conformance validate`
   - `pnpm -C examples/openai-tools start`
   - `pnpm -C examples/langgraph start`
5. Open a PR with:
   - problem statement
   - scope of change
   - validation results
   - any compatibility notes

## Protocol Change Rules

Any change that affects protocol semantics must include:

- corresponding updates in `SPEC.md` (and protocol docs when applicable)
- conformance vector updates in `packages/conformance/vectors`
- backward compatibility review and explicit migration notes when needed

Protocol-semantic changes without spec and conformance alignment should not be merged.

## Adapter Contributions

Adapter work must preserve the PDP/PEP boundary and fail-closed execution.

- PDP: policy decision (`evaluate` / `evaluatePure`)
- PEP: execution gate (`verifyAuthorization` before side effects)

Use the adapter architecture and verification docs:

- `docs/adapter-reference-architecture.md`
- `docs/adapters/adapter-verification.md`

## Security Reporting

For vulnerability disclosure and security handling, see `SECURITY.md`.

## Updating Architecture Diagrams

Use Excalidraw for architecture diagrams in `docs/diagrams/`.

When modifying a diagram:

1. Open https://excalidraw.com
2. Load the corresponding `.excalidraw` file
3. Make changes
4. Export `.svg` with scene data embedded
5. Commit both files (`.excalidraw` and `.svg`) in the same change

Do not add large PNG assets for architecture diagrams. SVG is the repository standard.
