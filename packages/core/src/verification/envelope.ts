// SPDX-License-Identifier: Apache-2.0
import { canonicalJson } from "../crypto/hashes.js";
import type { AuditEntry } from "../audit/AuditLog.js";
import { validateVerificationEnvelopeWireJson } from "../schemas/validate.js";
import { SIGNING_DOMAINS, signEd25519 } from "../crypto/signatures.js";

/** @public */
export type VerificationEnvelopeV1 = {
  formatVersion: 1;
  snapshot: Uint8Array;
  events: AuditEntry[];
  issuer?: string;
  alg?: "Ed25519";
  kid?: string;
  signature?: string;
};

type EnvelopeWire = {
  formatVersion: 1;
  snapshot: string;
  events: AuditEntry[];
  issuer?: string;
  alg?: "Ed25519";
  kid?: string;
  signature?: string;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function assertEnvelope(value: unknown): EnvelopeWire {
  if (!isObject(value) || Array.isArray(value)) {
    throw new Error("invalid verification envelope");
  }

  if (!("formatVersion" in value) || value.formatVersion !== 1) {
    throw new Error("invalid verification envelope: unsupported formatVersion");
  }

  if (typeof value.snapshot !== "string") {
    throw new Error("invalid verification envelope: snapshot");
  }

  if (!Array.isArray(value.events)) {
    throw new Error("invalid verification envelope: events");
  }

  for (let i = 0; i < value.events.length; i++) {
    const e = value.events[i];
    if (!isObject(e) || Array.isArray(e)) {
      throw new Error(`invalid verification envelope: events[${i}]`);
    }
  }

  return {
    formatVersion: 1,
    snapshot: value.snapshot,
    events: value.events as AuditEntry[],
    issuer: typeof value.issuer === "string" ? value.issuer : undefined,
    alg: value.alg === "Ed25519" ? "Ed25519" : undefined,
    kid: typeof value.kid === "string" ? value.kid : undefined,
    signature: typeof value.signature === "string" ? value.signature : undefined
  };
}

function toWire(envelope: VerificationEnvelopeV1): EnvelopeWire {
  const wire: EnvelopeWire = {
    formatVersion: 1,
    snapshot: Buffer.from(envelope.snapshot).toString("base64"),
    events: envelope.events.map((e) => structuredClone(e))
  };
  if (envelope.issuer !== undefined) wire.issuer = envelope.issuer;
  if (envelope.alg !== undefined) wire.alg = envelope.alg;
  if (envelope.kid !== undefined) wire.kid = envelope.kid;
  if (envelope.signature !== undefined) wire.signature = envelope.signature;
  return wire;
}

/** @public */
export function envelopeSigningPayload(envelope: VerificationEnvelopeV1): Omit<EnvelopeWire, "signature"> {
  const wire = toWire(envelope);
  const payload: Omit<EnvelopeWire, "signature"> = {
    formatVersion: wire.formatVersion,
    snapshot: wire.snapshot,
    events: wire.events
  };
  if (wire.issuer !== undefined) payload.issuer = wire.issuer;
  if (wire.alg !== undefined) payload.alg = wire.alg;
  if (wire.kid !== undefined) payload.kid = wire.kid;
  return payload;
}

/** @public */
export function signEnvelopeEd25519(
  envelope: VerificationEnvelopeV1,
  opts: { issuer: string; kid: string; privateKeyPem: string }
): VerificationEnvelopeV1 {
  const unsigned: VerificationEnvelopeV1 = {
    ...envelope,
    issuer: opts.issuer,
    alg: "Ed25519",
    kid: opts.kid,
    signature: undefined
  };
  const sig = signEd25519(SIGNING_DOMAINS.ENVELOPE_V1, envelopeSigningPayload(unsigned), opts.privateKeyPem);
  return { ...unsigned, signature: sig };
}

/** @public */
export function encodeEnvelope(envelope: VerificationEnvelopeV1): Uint8Array {
  if (envelope.formatVersion !== 1) {
    throw new Error("invalid verification envelope: unsupported formatVersion");
  }
  if (!(envelope.snapshot instanceof Uint8Array)) {
    throw new Error("invalid verification envelope: snapshot");
  }
  if (!Array.isArray(envelope.events)) {
    throw new Error("invalid verification envelope: events");
  }

  const wire = toWire(envelope);

  return new TextEncoder().encode(canonicalJson(wire));
}

/** @public */
export function decodeEnvelope(bytes: Uint8Array): VerificationEnvelopeV1 {
  const parsed = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  const issues = validateVerificationEnvelopeWireJson(parsed);
  if (issues.length > 0) {
    const first = issues[0];
    throw new Error(`invalid verification envelope: ${first.path}: ${first.message}`);
  }
  const wire = assertEnvelope(parsed);

  return {
    formatVersion: 1,
    snapshot: Uint8Array.from(Buffer.from(wire.snapshot, "base64")),
    events: wire.events.map((e) => structuredClone(e)),
    issuer: wire.issuer,
    alg: wire.alg,
    kid: wire.kid,
    signature: wire.signature
  };
}
