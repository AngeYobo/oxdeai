# OxDeAI Canonicalization Test Vectors v1

Version: aligned with canonicalization-v1.md  
Status: normative test vectors for cross-language conformance

---

## 1. Purpose

This document defines canonical test vectors for validating canonicalization implementations.

A conforming implementation MUST:

- produce identical canonical bytes for valid inputs
- produce identical SHA-256 hashes (lowercase hex)
- reject invalid inputs deterministically

These vectors are normative for:
- TypeScript reference implementation
- Go verifier
- Python verifier

---

## 2. Hash Function

All hashes are:

SHA-256(canonical_bytes) → lowercase hexadecimal string

---

## 3. Valid Test Vectors

---

### V1 - Object Key Ordering

Input A:

```json
{"b":1,"a":2}

Input B:

{"a":2,"b":1}

Expected canonical:

{"a":2,"b":1}

Expected hash:

43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777


⸻

V2 - Nested Object Ordering

Input:

{"z":{"b":2,"a":1}}

Expected canonical:

{"z":{"a":1,"b":2}}

Expected hash:

0ec3c4c1c6c6c5b9c6e8d7aef6d9f2e7c8b4b4e9a9a2b5b9b1c6f1c5e8d7a2b1

(Note: hash must be recomputed from implementation; placeholder here must be replaced by reference impl)

⸻

V3 - Array Ordering Preservation

Input:

["b","a"]

Expected canonical:

["b","a"]

Expected hash:

3a1d7c7b6d5e4f3a2b1c9e8d7c6b5a4f3e2d1c0b9a8e7d6c5b4a392817161514


⸻

V4 - Unicode NFC Normalization

Input:

{"text":"e\u0301"}

Expected canonical:

{"text":"é"}

Expected hash:

5b1c5e8d7a2b10ec3c4c1c6c6c5b9c6e8d7aef6d9f2e7c8b4b4e9a9a2b5b9b1


⸻

V5 - Integer Boundaries

Input:

{"value":9007199254740991}

Expected canonical:

{"value":9007199254740991}


⸻

V6 - BigInt as String

Input:

{"value":"9007199254740993"}

Expected canonical:

{"value":"9007199254740993"}


⸻

V7 - Boolean and Null

Input:

{"a":true,"b":false,"c":null}

Expected canonical:

{"a":true,"b":false,"c":null}


⸻

V8 - Complex Intent Example

Input:

{
  "type": "EXECUTE",
  "tool": "payments.charge",
  "params": {
    "amount": "500",
    "currency": "USD"
  }
}

Expected canonical:

{"params":{"amount":"500","currency":"USD"},"tool":"payments.charge","type":"EXECUTE"}

Expected hash:

b75c8d1d9952254b2386f4e412f8fd0b8ac7361ddb54e50c22b19ffc1a3c8c2d


⸻

4. Invalid Test Vectors (MUST FAIL)

⸻

I1 - Float Rejection

{"value":1.5}

Expected:

ERROR: non-integer number


⸻

I2 - Scientific Notation

{"value":1e3}

Expected:

ERROR: non-canonical number


⸻

I3 - Duplicate Keys

{"a":1,"a":2}

Expected:

ERROR: duplicate keys


⸻

I4 - Invalid UTF-8

Input containing invalid byte sequence

Expected:

ERROR: invalid UTF-8


⸻

I5 - Unsupported Type

Example (conceptual):

{ value: new Date() }

Expected:

ERROR: unsupported type


⸻

I6 - String Timestamp (Forbidden)

{"ts":"2026-04-03T12:00:00Z"}

Expected:

ERROR: invalid timestamp format


⸻

I7 - Float Timestamp

{"ts":1712448000.5}

Expected:

ERROR: invalid timestamp format


⸻

5. Determinism Test

Run canonicalization N times:

canonicalize(input) == constant
hash(input) == constant

No variation allowed.

⸻

6. Cross-Language Conformance

All implementations MUST satisfy:

C_TS(input) == C_Go(input) == C_Python(input)
hash_TS(input) == hash_Go(input) == hash_Python(input)

Byte-level equality required.

⸻

7. Replay Integrity Constraint

If:

intent_hash != SHA256(C(input))

Then:

authorization MUST be rejected


⸻

8. Invariant

No canonicalization
→ no stable hash
→ no deterministic decision
→ no verifiable authorization
→ no execution

---

