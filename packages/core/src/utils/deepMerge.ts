/**
 * deepMerge — pure recursive merge for policy state deltas.
 *
 * Used by the decision runner to accumulate module state deltas in-order.
 * Input objects are NOT mutated; a fresh object is returned.
 *
 * Rules:
 *  - Plain object + plain object → recursive merge
 *  - Any other combination → patch wins (leaf overwrite)
 */

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return isObject(v) && !Array.isArray(v);
}

function mergeInto(target: Record<string, unknown>, source: Record<string, unknown>): void {
  for (const key of Object.keys(source)) {
    const src = source[key];
    const dst = target[key];
    if (isPlainObject(src) && isPlainObject(dst)) {
      mergeInto(dst, src);
      continue;
    }
    target[key] = src;
  }
}

export function deepMerge<T>(base: T, patch: Partial<T>): T {
  if (!isPlainObject(base) || !isPlainObject(patch)) return (patch as T) ?? base;
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  mergeInto(out, patch as Record<string, unknown>);
  return out as T;
}
