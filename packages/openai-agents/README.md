# @oxdeai/openai-agents

**Thin OpenAI Agents SDK binding for [@oxdeai/guard](https://github.com/AngeYobo/oxdeai/blob/main/packages/guard/README.md).**

This package connects OpenAI Agents SDK tool calls to the OxDeAI universal
execution guard. It contains no authorization logic - all policy evaluation
and PEP enforcement is delegated to `@oxdeai/guard`.

---

## What this package does

OpenAI Agents SDK tool calls (`{ name, input, call_id }`) carry no agent
identity and use a different shape from OxDeAI's `ProposedAction`. This adapter:

1. Injects `agentId` from config into every call (tool calls carry no agent identity)
2. Maps `toolCall.input` → `args` (OpenAI uses `input`, not `args`)
3. Maps `toolCall.call_id` → `context.intent_id` (OpenAI uses `call_id`, not `id`)
4. Passes the resulting `ProposedAction` to `OxDeAIGuard`

Everything else - policy evaluation, authorization verification, state
persistence, fail-closed behavior - happens inside `@oxdeai/guard`.

---

## Installation

```sh
pnpm add @oxdeai/openai-agents @oxdeai/core
```

---

## Usage

```ts
import { createOpenAIAgentsGuard } from "@oxdeai/openai-agents";

const guard = createOpenAIAgentsGuard({
  engine,      // PolicyEngine from @oxdeai/core
  getState,    // () => State | Promise<State>
  setState,    // (state: State) => void | Promise<void>
  agentId: "gpu-agent-1",
});

// In your tool execution handler:
const result = await guard(
  { name: "provision_gpu", input: { asset: "a100", region: "us-east-1" }, call_id: "call-xyz" },
  () => provisionGpu("a100", "us-east-1")
);
```

The `execute` callback is only invoked when the policy engine returns ALLOW
**and** the authorization artifact passes verification. On DENY, `OxDeAIDenyError`
is thrown and the callback is never called.

---

## With estimated cost

Attach `estimatedCost` and `resourceType` directly on the tool call to give
the default normalizer richer context:

```ts
await guard(
  {
    name: "provision_gpu",
    input: { asset: "a100", region: "us-east-1" },
    call_id: "call-xyz",
    estimatedCost: 500,
    resourceType: "gpu",
  },
  () => provisionGpu("a100", "us-east-1")
);
```

---

## With a custom intent mapper

Use `mapActionToIntent` when you need full control over how a tool call maps
to an OxDeAI `Intent`:

```ts
const guard = createOpenAIAgentsGuard({
  engine,
  getState,
  setState,
  agentId: "gpu-agent-1",
  mapActionToIntent(action) {
    // action.name, action.args (from toolCall.input), action.context.agent_id available
    return buildProvisionIntent(action.args.asset as string, action.args.region as string);
  },
});
```

---

## Error handling

```ts
import {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAINormalizationError,
} from "@oxdeai/openai-agents";

try {
  await guard(toolCall, execute);
} catch (err) {
  if (err instanceof OxDeAIDenyError) {
    // Policy denied - err.reasons contains the violation codes
    console.error("denied:", err.reasons);
  } else if (err instanceof OxDeAIAuthorizationError) {
    // Authorization artifact missing or invalid - hard security failure
    throw err;
  }
}
```

---

## Deterministic boundary semantics

This adapter preserves the same deterministic, offline-verifiable boundary
semantics as every other OxDeAI protocol demo:

- **No Authorization = no execution**, even on ALLOW
- **DENY** blocks the execute callback before it is called
- **State transitions** happen only after successful execution
- **Envelope verification** remains offline and deterministic

All of this is guaranteed by `@oxdeai/guard` - this package adds nothing on top.

---

## Architecture boundary

This package is a **thin binding only**. Do not add:

- Authorization logic
- Policy evaluation logic
- `verifyAuthorization` calls
- Runtime security semantics beyond the ToolCall → ProposedAction mapping

All of that lives in `@oxdeai/guard`.

---

## See also

- [OpenAI Agents SDK integration guide](https://github.com/AngeYobo/oxdeai/blob/main/docs/integrations/openai-agents-sdk.md)
- [Adapter stack architecture](https://github.com/AngeYobo/oxdeai/blob/main/docs/integrations/adapter-stack.md)
- [Adapter reference architecture](https://github.com/AngeYobo/oxdeai/blob/main/docs/adapter-reference-architecture.md)
- [Root README](https://github.com/AngeYobo/oxdeai/blob/main/README.md)
