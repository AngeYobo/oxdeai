# Adoption Checklist

This checklist summarizes the current v1.4 adoption-readiness evidence for maintained integrations.

## Supported Adapters

- OpenAI tools
- LangGraph
- CrewAI
- OpenAI Agents SDK
- AutoGen
- OpenClaw

## Shared Scenario Outcome

Maintained adapters implement the same semantic demo result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Reference:

- [Shared demo scenario](./shared-demo-scenario.md)

## Validation Entry Points

- `pnpm validate:adapters`
- `pnpm -C examples/openai-tools validate`
- `pnpm -C examples/langgraph validate`
- `pnpm -C examples/crewai validate`
- `pnpm -C examples/openai-agents-sdk validate`
- `pnpm -C examples/autogen validate`
- `pnpm -C examples/openclaw validate`

## Reference Documentation

- [Integrations index](./README.md)
- [Adapter validation](./adapter-validation.md)
- [Shared adapter contract](../adapter-contract.md)
- [Production PEP wiring guide](../pep-production-guide.md)
- [Case writeups](../cases/README.md)
