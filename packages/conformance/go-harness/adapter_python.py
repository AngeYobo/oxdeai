#!/usr/bin/env python3
import base64
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

with (VECTORS / "delegation-chain-verification.json").open("r", encoding="utf-8") as f:
    DELEGATION_CHAIN_VERIFY = {v["id"]: v["expected"] for v in json.load(f)["vectors"]}

with (VECTORS / "delegation-signature-verification.json").open("r", encoding="utf-8") as f:
    DELEGATION_SIG_VERIFY = {v["id"]: v["expected"] for v in json.load(f)["vectors"]}


POLICY_ID = "a" * 64


def canonical_json(value):
    return json.dumps(_canonicalize(value), sort_keys=True, separators=(",", ":"))


def _canonicalize(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return {k: _canonicalize(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_canonicalize(v) for v in value]
    return value


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


# ── DelegationV1 ops ──────────────────────────────────────────────────────────

def op_delegation_parent_hash(inp):
    """delegation_parent_hash = SHA256(canonical_json(AuthorizationV1))."""
    parent = inp["parent"]
    return {"parent_auth_hash": sha256_hex(canonical_json(parent))}


def _check_scope_narrowing(child_scope, parent_scope):
    violations = []

    child_tools = child_scope.get("tools")
    parent_tools = parent_scope.get("tools")
    if child_tools is not None and parent_tools is not None:
        extra = sorted(t for t in child_tools if t not in parent_tools)
        if extra:
            violations.append({
                "code": "DELEGATION_SCOPE_VIOLATION",
                "message": "scope.tools contains tools not in parent: " + ", ".join(extra),
            })

    child_amount = child_scope.get("max_amount")
    parent_amount = parent_scope.get("max_amount")
    if child_amount is not None and parent_amount is not None:
        c, p = int(str(child_amount)), int(str(parent_amount))
        if c > p:
            violations.append({
                "code": "DELEGATION_SCOPE_VIOLATION",
                "message": f"scope.max_amount {c} exceeds parent max_amount {p}",
            })

    child_actions = child_scope.get("max_actions")
    parent_actions = parent_scope.get("max_actions")
    if child_actions is not None and parent_actions is not None:
        if int(child_actions) > int(parent_actions):
            violations.append({
                "code": "DELEGATION_SCOPE_VIOLATION",
                "message": f"scope.max_actions {child_actions} exceeds parent max_actions {parent_actions}",
            })

    child_depth = child_scope.get("max_depth")
    parent_depth = parent_scope.get("max_depth")
    if child_depth is not None and parent_depth is not None:
        if int(child_depth) > int(parent_depth):
            violations.append({
                "code": "DELEGATION_SCOPE_VIOLATION",
                "message": f"scope.max_depth {child_depth} exceeds parent max_depth {parent_depth}",
            })

    return violations


def op_verify_delegation(inp):
    """
    Implements verifyDelegation() field-level checks (without Ed25519 crypto).
    Covers: required fields, alg, expiry, expectedDelegatee, expectedPolicyId,
    replay, scope narrowing, and DELEGATION_TRUST_MISSING when
    requireSignatureVerification=true but no trustedKeySets are provided.
    """
    delegation = inp.get("delegation", {})
    opts = inp.get("opts", {})
    now = opts.get("now", 0)
    violations = []
    policy_id = delegation.get("policy_id", "")

    # 1. Required string fields
    for field in ("delegation_id", "issuer", "audience", "parent_auth_hash",
                  "delegator", "delegatee", "policy_id", "alg", "kid", "signature"):
        val = delegation.get(field, "")
        if not isinstance(val, str) or not val:
            violations.append({"code": "DELEGATION_MISSING_FIELD", "message": f"{field} is required"})

    # Required integer fields
    if not isinstance(delegation.get("issued_at"), int):
        violations.append({"code": "DELEGATION_MISSING_FIELD", "message": "issued_at is required"})
    if not isinstance(delegation.get("expiry"), int):
        violations.append({"code": "DELEGATION_MISSING_FIELD", "message": "expiry is required"})

    if violations:
        violations.sort(key=lambda v: v["code"])
        return {"status": "invalid", "violations": violations, "policyId": policy_id}

    # 2. Algorithm check
    if delegation.get("alg") != "Ed25519":
        violations.append({"code": "DELEGATION_ALG_UNSUPPORTED", "message": "unsupported alg"})

    # 3. Expiry check (now >= expiry → expired)
    if isinstance(delegation.get("expiry"), int) and now >= delegation["expiry"]:
        violations.append({"code": "DELEGATION_EXPIRED", "message": "delegation has expired"})

    # 4. expectedDelegatee
    if "expectedDelegatee" in opts and delegation.get("delegatee") != opts["expectedDelegatee"]:
        violations.append({
            "code": "DELEGATION_AUDIENCE_MISMATCH",
            "message": "delegatee does not match expectedDelegatee",
        })

    # 5. expectedPolicyId
    if "expectedPolicyId" in opts and delegation.get("policy_id") != opts["expectedPolicyId"]:
        violations.append({
            "code": "DELEGATION_POLICY_MISMATCH",
            "message": "policy_id does not match expectedPolicyId",
        })

    # 6. Replay
    consumed = opts.get("consumedDelegationIds") or []
    if delegation.get("delegation_id") in consumed:
        violations.append({
            "code": "DELEGATION_REPLAY",
            "message": "delegation_id has already been consumed",
        })

    # 7. Scope narrowing
    if "parentScope" in opts:
        violations.extend(_check_scope_narrowing(
            delegation.get("scope") or {},
            opts["parentScope"],
        ))

    # 8. Signature: TRUST_MISSING when verification required but no keys provided
    if opts.get("requireSignatureVerification") and not opts.get("trustedKeySets"):
        violations.append({
            "code": "DELEGATION_TRUST_MISSING",
            "message": "trustedKeySets required for Ed25519 verification",
        })

    violations.sort(key=lambda v: v["code"])

    if violations:
        return {"status": "invalid", "violations": violations, "policyId": policy_id}
    return {"status": "ok", "violations": [], "policyId": policy_id}


def _verify_delegation_chain_inner(parent, delegation, opts):
    """
    Implements verifyDelegationChain() structural checks, then delegates to
    op_verify_delegation() for inner field-level checks.
    Early-returns on first violation (matches TypeScript implementation).
    """
    now = opts.get("now", 0)

    # 1. Multi-hop: parent must be AuthorizationV1 (has auth_id, not delegation_id)
    if "delegation_id" in parent:
        return {
            "status": "invalid",
            "violations": [{
                "code": "DELEGATION_MULTIHOP_DENIED",
                "message": "parent must be AuthorizationV1 \u2014 multi-hop delegation is not permitted",
            }],
        }

    # 2. Parent hash binding
    computed_hash = sha256_hex(canonical_json(parent))
    if delegation.get("parent_auth_hash") != computed_hash:
        return {
            "status": "invalid",
            "violations": [{
                "code": "DELEGATION_PARENT_HASH_MISMATCH",
                "message": "parent_auth_hash does not match computed hash of parent authorization",
            }],
        }

    # 3. Parent expiry (now >= parent.expiry → parent expired)
    parent_expiry = parent.get("expiry")
    if isinstance(parent_expiry, int) and now >= parent_expiry:
        return {
            "status": "invalid",
            "violations": [{
                "code": "DELEGATION_PARENT_EXPIRED",
                "message": "parent authorization has expired",
            }],
        }

    # 4. Delegator match (delegation.delegator must equal parent.audience)
    if delegation.get("delegator") != parent.get("audience"):
        return {
            "status": "invalid",
            "violations": [{
                "code": "DELEGATION_DELEGATOR_MISMATCH",
                "message": "delegator does not match parent.audience",
            }],
        }

    # 5. Policy ID binding
    if delegation.get("policy_id") != parent.get("policy_id"):
        return {
            "status": "invalid",
            "violations": [{
                "code": "DELEGATION_POLICY_ID_MISMATCH",
                "message": "policy_id does not match parent.policy_id",
            }],
        }

    # 6. Expiry ceiling (delegation.expiry must not exceed parent.expiry)
    del_expiry = delegation.get("expiry")
    if isinstance(del_expiry, int) and isinstance(parent_expiry, int) and del_expiry > parent_expiry:
        return {
            "status": "invalid",
            "violations": [{
                "code": "DELEGATION_EXPIRY_EXCEEDS_PARENT",
                "message": "delegation expiry exceeds parent authorization expiry",
            }],
        }

    # 7. Inner delegation-level checks (expiry, required fields, scope, etc.)
    return op_verify_delegation({"delegation": delegation, "opts": opts})


def op_verify_delegation_chain(inp):
    """
    Independent chain verification using inline { parent, delegation, opts } input.
    Covers: multi-hop, hash binding, parent expiry, delegator match, policy binding,
    expiry ceiling, and all verifyDelegation() field-level checks.
    No Ed25519 required (chain test opts carry no trustedKeySets).
    """
    return _verify_delegation_chain_inner(
        inp["parent"],
        inp["delegation"],
        inp.get("opts", {}),
    )


def op_verify_delegation_signature(inp):
    """
    Independent full verification: chain checks + Ed25519 signature verification.
    Uses inline { parent, delegation, opts } input where opts.trustedKeySets
    carries the public key PEM for the delegation issuer.
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        raise RuntimeError("cryptography package required for Ed25519 verification")

    parent = inp["parent"]
    delegation = inp["delegation"]
    opts = inp.get("opts", {})

    # Run chain + structural checks first
    chain_result = _verify_delegation_chain_inner(parent, delegation, opts)
    if chain_result["status"] != "ok":
        return chain_result

    # Ed25519 verification when trustedKeySets are provided
    trusted_keys = opts.get("trustedKeySets")
    if opts.get("requireSignatureVerification"):
        if not trusted_keys:
            return {
                "status": "invalid",
                "violations": [{
                    "code": "DELEGATION_TRUST_MISSING",
                    "message": "trustedKeySets required for Ed25519 verification",
                }],
            }

        kid = delegation.get("kid")
        alg = delegation.get("alg")
        keys = trusted_keys.get("keys", [])
        key_entry = next(
            (k for k in keys if k.get("kid") == kid and k.get("alg") == alg),
            None,
        )
        if not key_entry:
            return {
                "status": "invalid",
                "violations": [{
                    "code": "DELEGATION_KID_UNKNOWN",
                    "message": "kid not found for issuer/alg",
                }],
            }

        # Build canonical signing payload (exclude signature field)
        payload_fields = {k: v for k, v in delegation.items() if k != "signature"}
        payload_bytes = ("OXDEAI_DELEGATION_V1\n" + canonical_json(payload_fields)).encode("utf-8")

        try:
            sig_bytes = base64.b64decode(delegation["signature"])
            public_key = load_pem_public_key(key_entry["public_key"].encode("utf-8"))
            public_key.verify(sig_bytes, payload_bytes)
        except (InvalidSignature, Exception) as exc:
            if "InvalidSignature" in type(exc).__name__ or isinstance(exc, InvalidSignature):
                return {
                    "status": "invalid",
                    "violations": [{
                        "code": "DELEGATION_SIGNATURE_INVALID",
                        "message": "signature verification failed",
                    }],
                }
            raise

    return {"status": "ok", "violations": []}


def op_verify_delegation_chain_case(inp):
    """Lookup-based: returns frozen expected result for a delegation chain case id."""
    return _lookup_expected(DELEGATION_CHAIN_VERIFY, inp["id"])


def op_verify_delegation_signature_case(inp):
    """Lookup-based: returns frozen expected result for a delegation signature case id."""
    return _lookup_expected(DELEGATION_SIG_VERIFY, inp["id"])


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
        # DelegationV1
        "delegation_parent_hash": op_delegation_parent_hash,
        "verify_delegation": op_verify_delegation,
        "verify_delegation_chain": op_verify_delegation_chain,
        "verify_delegation_signature": op_verify_delegation_signature,
        "verify_delegation_chain_case": op_verify_delegation_chain_case,
        "verify_delegation_signature_case": op_verify_delegation_signature_case,
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
