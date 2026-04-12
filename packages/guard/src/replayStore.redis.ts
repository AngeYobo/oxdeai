// SPDX-License-Identifier: Apache-2.0
/**
 * replayStore.redis.ts
 *
 * Production-grade ReplayStore backed by Redis.
 *
 * Atomicity guarantee:
 *   SET key value NX EX ttl is a single atomic Redis command.
 *   Across any number of guard instances sharing the same Redis cluster,
 *   exactly one caller will receive "OK" for a given key; all others receive
 *   null. This eliminates the TOCTOU window present in read-then-write patterns.
 *
 * Key schema:
 *   replay:auth:<auth_id>           — AuthorizationV1 single-use tokens
 *   replay:delegation:<delegation_id> — DelegationV1 single-use tokens
 *
 * TTL policy:
 *   ttl = max(1, expiry - now)
 *   Keys are automatically evicted by Redis once the artifact expires.
 *   A minimum of 1 second is enforced so that already-expired artifacts
 *   never create zero-TTL or infinite-TTL keys.
 *
 * Fail-closed:
 *   Any Redis error (network failure, timeout, cluster failover) is re-thrown.
 *   The guard catches this and raises OxDeAIAuthorizationError, blocking execution.
 *   There is no fallback, no best-effort path, no silent memory store.
 *
 * Client compatibility:
 *   The RedisClient interface matches the ioredis positional argument style:
 *     client.set(key, value, "NX", "EX", ttlSeconds) → Promise<"OK" | null>
 *
 *   node-redis v4 adapter:
 *     const client: RedisClient = {
 *       set: (k, v, _nx, _ex, ttl) =>
 *         nodeRedisClient.set(k, v, { NX: true, EX: ttl }),
 *     };
 *
 * Clock skew:
 *   TTL is derived from artifact expiry (absolute Unix timestamp). If the
 *   guard host clock is skewed relative to the issuer, the TTL may be shorter
 *   or longer than intended. A skew of ±30 seconds is typical and acceptable
 *   given that authorization artifacts already carry explicit expiry checks in
 *   strictVerifyAuthorization. The Redis TTL only governs key eviction, not
 *   authorization validity.
 */

import type { ReplayStore } from "./replayStore.js";

// ---------------------------------------------------------------------------
// Minimal Redis client interface
// ---------------------------------------------------------------------------

/**
 * Minimal Redis client interface required by createRedisReplayStore.
 *
 * Intentionally narrow — only the SET NX EX command is required.
 * Compatible natively with ioredis and @redis/client (node-redis v4 wrapper).
 *
 * The caller owns the client lifecycle (connection, reconnection, shutdown).
 * The store does NOT create, pool, or close connections.
 */
export interface RedisClient {
  /**
   * SET key value NX EX seconds
   *
   * @returns "OK"  if the key was set (first use — consume allowed)
   * @returns null  if the key already existed (replay — consume denied)
   * @throws        on any Redis or network error
   */
  set(
    key: string,
    value: string,
    nx: "NX",
    ex: "EX",
    seconds: number
  ): Promise<"OK" | null>;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface RedisReplayStoreConfig {
  /** Pre-connected Redis client. The store does not manage its lifecycle. */
  client: RedisClient;
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/** Returns the Redis key for an auth_id. Not user-overridable. */
function authKey(authId: string): string {
  return `replay:auth:${authId}`;
}

/** Returns the Redis key for a delegation_id. Not user-overridable. */
function delegationKey(delegationId: string): string {
  return `replay:delegation:${delegationId}`;
}

/**
 * Compute the TTL (seconds) to assign to a Redis key.
 *
 * Always at least 1 second — zero or negative TTLs would cause Redis to either
 * reject the command or create a key that expires immediately, which could allow
 * replay of already-expired artifacts on a subsequent request within the same
 * second.
 */
function computeTtl(expiry: number): number {
  const now = Math.floor(Date.now() / 1000);
  return Math.max(1, expiry - now);
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * createRedisReplayStore — production-grade, multi-instance-safe ReplayStore.
 *
 * Usage:
 *
 *   import { createClient } from "ioredis"; // or node-redis v4
 *   import { createRedisReplayStore } from "@oxdeai/guard/replayStore.redis";
 *
 *   const redis = new Redis({ host: "redis.internal", port: 6379 });
 *
 *   const guard = OxDeAIGuard({
 *     // ...
 *     replayStore: createRedisReplayStore({ client: redis }),
 *   });
 *
 * @param config.client  Pre-connected Redis client. Must remain connected for
 *                       the lifetime of the guard. The caller is responsible
 *                       for reconnection and graceful shutdown.
 */
export function createRedisReplayStore(config: RedisReplayStoreConfig): ReplayStore {
  const { client } = config;

  if (!client || typeof client.set !== "function") {
    throw new TypeError(
      "createRedisReplayStore: config.client must implement RedisClient (set method required)."
    );
  }

  return {
    async consumeAuthId(authId: string, opts: { expiry: number }): Promise<boolean> {
      const ttl = computeTtl(opts.expiry);
      const result = await client.set(authKey(authId), "1", "NX", "EX", ttl);
      return result === "OK";
    },

    async consumeDelegationId(delegationId: string, opts: { expiry: number }): Promise<boolean> {
      const ttl = computeTtl(opts.expiry);
      const result = await client.set(delegationKey(delegationId), "1", "NX", "EX", ttl);
      return result === "OK";
    },
  };
}
