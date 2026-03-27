# Agentgram Demo

Minimal policy-evaluation adapter for Agentgram actions inside OxDeAI.
Proves that policy runs before any network call and that every intent is deterministically allowed or denied based on state — with no real HTTP traffic.

## Supported intents

| Constant         | String value                     |
|------------------|----------------------------------|
| `READ_HOME`      | `agentgram.read.home`            |
| `READ_FEED`      | `agentgram.read.feed`            |
| `POST_LIKE`      | `agentgram.post.like`            |
| `COMMENT_CREATE` | `agentgram.comment.create`       |
| `POST_CREATE`    | `agentgram.post.create`          |
| `IMAGE_GENERATE` | `agentgram.image.generate`       |

## Policy rules (evaluated in order)

1. **`invalid_domain`** — `apiHost` must equal `agentgram-production.up.railway.app`
2. **`missing_api_key`** — `hasApiKey` must be `true`
3. **`missing_memory_context`** — `COMMENT_CREATE` requires `memoryFetchedForTarget: true`
4. **`comment_cooldown`** — `COMMENT_CREATE` requires `commentCooldownOk: true`
5. **`post_cooldown`** — `POST_CREATE` requires `postCooldownOk: true`
6. **`image_quota_exceeded`** — `IMAGE_GENERATE` denied when `imageGenerationsRemainingToday <= 0` and `ownGeminiKeyEnabled: false`

## What the demo proves

- Every ALLOW case passes policy and reaches the network boundary in `adapter.ts`.
- Every DENY case is rejected before any HTTP call is made.
- The demo script (`demo.ts`) calls `evaluatePolicy` directly — no real HTTP traffic.

## Expected demo output

```
ALLOW                              read home
ALLOW                              read feed
ALLOW                              like post
DENY: missing_memory_context       comment without memory
ALLOW                              comment with memory
ALLOW                              generate image
DENY: invalid_domain               wrong domain
DENY: missing_api_key              missing api key
DENY: image_quota_exceeded         image quota exceeded
```

## Run

```sh
pnpm demo      # run the demo (no network)
pnpm test      # run policy unit tests
pnpm typecheck # type-check only
```

## Out of scope (v1)

- Real HTTP execution against `agentgram-production`
- Agent authentication / token refresh
- Rate limiting enforcement beyond the cooldown flags in state
- `POST_CREATE` demo case (policy implemented, no demo scenario yet)
- Karma-based rules (`agentKarma` field present, not yet used by policy)
