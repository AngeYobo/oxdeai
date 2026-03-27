# Agentgram Demo

Minimal **OxDeAI adapter + guard integration** for Agentgram-style actions.

This example shows how to enforce a **deterministic authorization boundary before execution** using `@oxdeai/core` + `@oxdeai/sdk`.

No prompt guardrails.
No post-hoc checks.
No network required.

---

## What this demonstrates

* Agent proposes actions (`AgentgramAction`)
* Actions are mapped → `IntentBuilderInput`
* OxDeAI evaluates `(intent, state, policy)` deterministically
* Execution is **only reachable on ALLOW**
* DENY cases are blocked **before any side effect**

**No authorization → no execution**

---

## Architecture

```
AgentgramAction
   ↓
toIntentInput()          // adapter.ts (pure mapping)
   ↓
createGuard()           // @oxdeai/sdk
   ↓
PolicyEngine.evaluate   // @oxdeai/core (deterministic)
   ↓
ALLOW → execute()
DENY  → blocked (throw)
```

---

## Supported actions

| Action          | Tool value                 | Target example                       |
| --------------- | -------------------------- | ------------------------------------ |
| Read home       | `agentgram.read.home`      | `agentgram:/home`                    |
| Read feed       | `agentgram.read.feed`      | `agentgram:/feed`                    |
| Like post       | `agentgram.post.like`      | `agentgram:/posts/{postId}/like`     |
| Comment on post | `agentgram.comment.create` | `agentgram:/posts/{postId}/comments` |

---

## Deterministic guarantees

This demo uses real OxDeAI modules:

* **AllowlistModule** → enforces allowed targets
* **ReplayModule** → blocks reused nonces
* **Budget / limits modules** → configured but permissive

### Proven properties

* Same `(intent + state + policy)` → same decision
* Replay attempts are rejected (`REPLAY_NONCE`)
* Unknown targets are rejected (`ALLOWLIST_TARGET`)
* Execution is unreachable on DENY (fail-closed)

---

## Example output

```
ALLOW  agentgram.read.home
ALLOW  agentgram.read.feed
ALLOW  agentgram.post.like
ALLOW  agentgram.comment.create
DENY   agentgram.read.home [replay nonce=1n] | DENY: REPLAY_NONCE
DENY   agentgram.post.like [unknown postId] | DENY: ALLOWLIST_TARGET
```

---

## Key files

| File         | Responsibility                  |
| ------------ | ------------------------------- |
| `types.ts`   | `AgentgramAction` (input shape) |
| `intents.ts` | Tool constants                  |
| `policy.ts`  | `PolicyEngine`, `makeState()`   |
| `adapter.ts` | Mapping + guard wrapper         |
| `run.ts`     | Demo orchestration (no network) |
| `client.ts`  | HTTP layer (not used in demo)   |

---

## Execution boundary

The boundary is explicit:

```ts
guard(action, async () => execute())
```

* `guard(...)` → authorization phase
* `execute()` → only runs if ALLOW

There is **no path** to execution without passing the policy engine.

---

## Run

```sh
pnpm --dir examples/agentgram-demo exec tsx src/run.ts
```

Typecheck:

```sh
pnpm --dir examples/agentgram-demo run typecheck
```

---

## Design notes

### Action mapping

All actions are mapped to:

```ts
IntentBuilderInput {
  action_type: "PROVISION"
  amount: 0n
  tool: <Agentgram intent>
  target: <derived canonical target>
}
```

* `tool` → semantic action identity
* `target` → enforced by allowlist
* `nonce` → replay protection
* `amount` → unused (no cost model)

### action_type

`"PROVISION"` is used as a placeholder.

It is not semantically perfect.
It is the least incorrect option in the current enum:

```
"PAYMENT" | "PURCHASE" | "PROVISION" | "ONCHAIN_TX"
```

Future improvement: introduce `API_CALL` or `TOOL_CALL`.

---

## Out of scope

* Real HTTP execution
* Authentication / API keys
* Rate limiting beyond policy modules
* Economic cost modeling
* Multi-agent delegation

---

## Why this matters

Most agent systems:

* rely on prompts
* check after execution
* cannot guarantee outcomes

This demo shows a different model:

> **Deterministic authorization before execution**

* reproducible
* auditable
* fail-closed
* portable across runtimes

---

## Next step

Replace the mocked `execute()` in `run.ts` with real calls from `client.ts`.

No changes required to:

* policy
* adapter
* guard
* evaluation logic

Only the execution layer changes.
