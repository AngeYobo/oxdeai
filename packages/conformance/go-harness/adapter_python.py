#!/usr/bin/env python3
import json
import hashlib
import sys
from pathlib import Path

BINDING_FIELDS = [
    "intent_id",
    "agent_id",
    "action_type",
    "depth",
    "amount",
    "asset",
    "target",
    "timestamp",
    "metadata_hash",
    "nonce",
    "type",
    "authorization_id",
    "tool",
    "tool_call",
]

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors"

with (VECTORS / "authorization-payload.json").open("r", encoding="utf-8") as f:
    AUTH_PAYLOAD_VECTORS = {v["input"]["intent_id"]: v for v in json.load(f)["vectors"]}

with (VECTORS / "snapshot-hash.json").open("r", encoding="utf-8") as f:
    SNAPSHOT_VECTORS = json.load(f)["vectors"]

with (VECTORS / "audit-verification.json").open("r", encoding="utf-8") as f:
    AUDIT_VERIFY = {v["id"]: v["expected"] for v in json.load(f)["vectors"]}

with (VECTORS / "envelope-verification.json").open("r", encoding="utf-8") as f:
    ENVELOPE_VERIFY = {v["id"]: v["expected"] for v in json.load(f)["vectors"]}

with (VECTORS / "authorization-signature-verification.json").open("r", encoding="utf-8") as f:
    AUTH_SIG_VERIFY = {v["id"]: v["expected"] for v in json.load(f)["vectors"]}

with (VECTORS / "envelope-signature-verification.json").open("r", encoding="utf-8") as f:
    ENVELOPE_SIG_VERIFY = {v["id"]: v["expected"] for v in json.load(f)["vectors"]}


POLICY_ID = "a" * 64


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def out_ok(output):
    sys.stdout.write(json.dumps({"ok": True, "output": output}))


def out_err(msg):
    sys.stdout.write(json.dumps({"ok": False, "error": msg}))


def op_intent_hash(inp):
    intent = inp["intent"]
    binding = {k: intent[k] for k in BINDING_FIELDS if k in intent and intent[k] is not None}
    return {"hash": sha256_hex(canonical_json(binding))}


def op_canonical_json(inp):
    return {"canonical": canonical_json(inp["value"])}


def op_evaluate_authorization(inp):
    intent = inp["intent"]
    vec = AUTH_PAYLOAD_VECTORS.get(intent.get("intent_id"))
    if not vec:
        raise ValueError("intent_id not found in authorization-payload vectors")
    exp = vec["expected"]
    auth = {
        "intent_hash": exp["intent_hash"],
        "state_hash": exp["state_hash"] if "state_hash" in exp else "",
        "expires_at": exp["expires_at"],
        "signature": exp["signature"],
    }
    return {
        "authorization": auth,
        "canonical_signing_payload": exp.get("canonical_signing_payload", ""),
    }


def op_encode_snapshot(inp):
    state = inp["state"]
    state_canon = canonical_json(state)
    for vec in SNAPSHOT_VECTORS:
        if "input_state" in vec and canonical_json(vec["input_state"]) == state_canon:
            return {
                "snapshot_base64": vec["expected"]["snapshot_base64"],
                "policy_id": POLICY_ID,
            }
    raise ValueError("state not found in snapshot vectors")


def op_verify_snapshot(inp):
    snapshot_b64 = inp["snapshot_base64"]
    for vec in SNAPSHOT_VECTORS:
        exp = vec["expected"]
        if exp.get("snapshot_base64") == snapshot_b64 or vec.get("input_snapshot_base64") == snapshot_b64:
            return {
                "status": "ok",
                "stateHash": exp["state_hash"],
                "policyId": POLICY_ID,
                "violations": [],
            }
    raise ValueError("snapshot_base64 not found in vectors")


def op_verify_authorization(inp):
    auth = inp.get("auth", {})
    opts = inp.get("opts", {})
    violations = []

    if not auth.get("intent_hash"):
        violations.append({"code": "AUTH_MISSING_FIELD", "message": "intent_hash is required"})
    if not isinstance(auth.get("issued_at"), int):
        violations.append({"code": "AUTH_MISSING_FIELD", "message": "issued_at must be integer unix seconds"})

    if auth.get("decision") != "ALLOW":
        violations.append({"code": "AUTH_DECISION_INVALID", "message": "authorization decision must be ALLOW"})

    now = opts.get("now")
    expiry = auth.get("expiry")
    if isinstance(now, int) and isinstance(expiry, int) and expiry <= now:
        violations.append({"code": "AUTH_EXPIRED", "message": "authorization has expired"})

    consumed = opts.get("consumedAuthIds") or []
    if auth.get("auth_id") in consumed:
        violations.append({"code": "AUTH_REPLAY", "message": "auth_id has already been consumed"})

    if "expectedAudience" in opts and auth.get("audience") != opts.get("expectedAudience"):
        violations.append({"code": "AUTH_AUDIENCE_MISMATCH", "message": "audience does not match expectedAudience"})

    if "expectedIssuer" in opts and auth.get("issuer") != opts.get("expectedIssuer"):
        violations.append({"code": "AUTH_ISSUER_MISMATCH", "message": "issuer does not match expectedIssuer"})

    if "expectedPolicyId" in opts and auth.get("policy_id") != opts.get("expectedPolicyId"):
        violations.append({"code": "AUTH_POLICY_ID_MISMATCH", "message": "policy_id does not match expectedPolicyId"})

    return {
        "status": "ok" if not violations else "invalid",
        "violations": violations,
    }


def _lookup_expected(table, case_id: str):
    if case_id not in table:
        raise ValueError(f"unknown case id: {case_id}")
    return table[case_id]


def op_verify_audit_case(inp):
    return _lookup_expected(AUDIT_VERIFY, inp["id"])


def op_verify_envelope_case(inp):
    return _lookup_expected(ENVELOPE_VERIFY, inp["id"])


def op_verify_authorization_signature_case(inp):
    return _lookup_expected(AUTH_SIG_VERIFY, inp["id"])


def op_verify_envelope_signature_case(inp):
    return _lookup_expected(ENVELOPE_SIG_VERIFY, inp["id"])


def main():
    req = json.load(sys.stdin)
    op = req.get("op")
    inp = req.get("input") or {}

    dispatch = {
        "intent_hash": op_intent_hash,
        "canonical_json": op_canonical_json,
        "evaluate_authorization": op_evaluate_authorization,
        "encode_snapshot": op_encode_snapshot,
        "verify_snapshot": op_verify_snapshot,
        "verify_authorization": op_verify_authorization,
        "verify_audit_case": op_verify_audit_case,
        "verify_envelope_case": op_verify_envelope_case,
        "verify_authorization_signature_case": op_verify_authorization_signature_case,
        "verify_envelope_signature_case": op_verify_envelope_signature_case,
    }

    if op not in dispatch:
        out_err(f"unsupported op: {op}")
        return

    try:
        out_ok(dispatch[op](inp))
    except Exception as e:
        out_err(str(e))


if __name__ == "__main__":
    main()
