// SPDX-License-Identifier: Apache-2.0

/**
 * ReplayStore — pluggable replay-prevention backend for the OxDeAI guard.
 *
 * The guard calls consumeAuthId (and optionally consumeDelegationId) before
 * every execution. Implementations MUST be fail-closed: if the store is
 * unavailable, throw rather than returning a permissive result. Any thrown
 * error is caught by the guard and re-raised as OxDeAIAuthorizationError,
 * blocking execution.
 *
 * Atomicity:
 *   From the guard's perspective each call is a single check-and-consume
 *   operation. Durable backends should implement this using compare-and-swap
 *   or an equivalent operation so that concurrent callers cannot both observe
 *   a "not yet consumed" result for the same ID.
 *
 * Durability tiers:
 *   - In-memory (default)  : single-process only; replay state lost on restart.
 *   - Redis / DynamoDB     : survives restarts and horizontal scaling.
 *   - Relational DB        : full ACID guarantees; suits regulated environments.
 */
export interface ReplayStore {
  /**
   * Atomically check-and-consume an auth_id.
   *
   * @param authId        The auth_id from the AuthorizationV1 artifact.
   * @param opts.expiry   Unix timestamp (seconds) when the auth expires.
   *                      Durable backends may use this to set a TTL on the
   *                      record so that expired entries are garbage-collected.
   * @returns `true`  if the auth_id was successfully consumed (first use).
   * @returns `false` if the auth_id was already consumed (replay detected).
   * @throws             if the store is unavailable — the guard will DENY.
   */
  consumeAuthId(authId: string, opts: { expiry: number }): Promise<boolean>;

  /**
   * Atomically check-and-consume a delegation_id.
   *
   * Optional. When absent, delegation replay is still prevented by
   * consumeAuthId on the parent authorization: consuming the parentAuth
   * once prevents the same delegation chain from being replayed.
   *
   * Implement this method when stricter delegation tracking is required
   * (e.g. when a parent auth may authorise multiple distinct delegations and
   * per-delegation replay tracking is needed independently of parentAuth).
   *
   * @param delegationId  The delegation_id from the DelegationV1 artifact.
   * @param opts.expiry   Unix timestamp (seconds) when the delegation expires.
   * @returns `true`  if the delegation_id was successfully consumed (first use).
   * @returns `false` if the delegation_id was already consumed (replay detected).
   * @throws             if the store is unavailable — the guard will DENY.
   */
  consumeDelegationId?(delegationId: string, opts: { expiry: number }): Promise<boolean>;
}

/**
 * createInMemoryReplayStore — default single-process replay store.
 *
 * Uses two in-memory Sets to track consumed IDs. Each factory call produces
 * an independent store instance, mirroring the prior per-guard-instance Sets.
 *
 * Suitable for:
 *   - Single-process deployments
 *   - Testing and development
 *
 * NOT suitable for:
 *   - Multi-process / horizontally-scaled deployments
 *   - Scenarios where replay prevention must survive process restarts
 *
 * For production deployments requiring durability, implement ReplayStore
 * backed by Redis, DynamoDB, a relational database, or equivalent.
 */
export function createInMemoryReplayStore(): ReplayStore {
  const consumedAuthIds = new Set<string>();
  const consumedDelegationIds = new Set<string>();

  return {
    async consumeAuthId(authId: string): Promise<boolean> {
      if (consumedAuthIds.has(authId)) return false;
      consumedAuthIds.add(authId);
      return true;
    },
    async consumeDelegationId(delegationId: string): Promise<boolean> {
      if (consumedDelegationIds.has(delegationId)) return false;
      consumedDelegationIds.add(delegationId);
      return true;
    },
  };
}
