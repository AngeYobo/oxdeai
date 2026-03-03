import type { AuditEvent } from "../audit/AuditLog.js";
import type { CanonicalState } from "../types/state.js";

export type MaybePromise<T> = T | Promise<T>;

export interface StateStore {
  get(): MaybePromise<CanonicalState | null>;
  set(state: CanonicalState): MaybePromise<void>;
}

export interface AuditSink {
  append(event: AuditEvent): MaybePromise<void>;
  flush?(): MaybePromise<void>;
}
