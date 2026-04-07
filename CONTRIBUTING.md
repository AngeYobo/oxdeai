# Contributing

## Setup

pnpm install  
pnpm build  
pnpm test  

## Core Principles

- deterministic evaluation only
- no side effects in policy
- fail-closed by default

## Validation

Before opening a PR:

pnpm -r build  
pnpm -r test  
pnpm -C packages/conformance validate  
pnpm validate:adapters  

## Guidelines

- keep changes minimal and focused
- separate protocol vs documentation changes
- preserve determinism guarantees
- update tests when behavior changes

## PRs

- include rationale
- reference affected artifacts (AuthorizationV1, DelegationV1, etc.)
- ensure reproducibility

## Scope

OxDeAI is:

- an execution authorization boundary

OxDeAI is not:

- a framework
- a runtime