# OxDeAI Canonicalization Specification v1

## 1. Purpose

This specification defines a deterministic canonicalization procedure for structured authorization inputs.

The canonicalization function transforms an input value into a unique UTF-8 encoded JSON byte sequence suitable for hashing, signing, replay protection, and cross-language verification.

The canonicalization procedure MUST guarantee:

- deterministic serialization
- byte-stability
- cross-language equality
- fail-closed rejection of unsupported inputs

---

## 2. Canonicalization Function

The canonicalization function is defined as:

C(input) -> canonical_bytes

Where:

- input is a structured value conforming to this specification
- canonical_bytes is the canonical UTF-8 encoded JSON representation

---

## 3. Equivalence

Two inputs are considered equivalent if:

C(x) == C(y)

No semantic equivalence beyond byte equality is assumed.

---

## 4. Output Format

The canonical output MUST be:

- valid JSON (RFC 8259)
- encoded as UTF-8
- emitted without BOM
- minified (no insignificant whitespace)
- serialized deterministically

---

## 5. Input Parsing Requirements

Inputs MUST be parsed deterministically before canonicalization.

- duplicate keys MUST be detected during parsing
- inputs that cannot be deterministically parsed MUST be rejected

Invalid UTF-8 sequences MUST cause canonicalization failure.

---

## 6. Serialization Rules (normative)

Implementations MUST apply the following rules, in order, to produce the canonical JSON bytes:

- Strings: normalize to Unicode NFC; encode as JSON strings.
- Object keys: NFC-normalize, reject duplicates after normalization, then sort keys by byte-wise UTF-8 order.
- Arrays: preserve element order.
- Numbers: only integers in the safe IEEE-754 range **[-9007199254740991, 9007199254740991]** are allowed; floats and `NaN`/`±Inf` MUST be rejected.
- BigInt (when present in runtime): serialize as JSON strings.
- Timestamps: if key == `"ts"`, the value MUST be an integer within the safe range; otherwise reject.
- Unsupported runtime types (function, symbol, undefined, etc.) MUST be rejected.
- Output MUST be minified (no insignificant whitespace) and UTF-8 encoded without BOM.

---

## 7. Error Codes (normative)

When rejecting inputs, implementations MUST fail closed and SHOULD use these canonical error codes to enable cross-language parity:

- `FLOAT_NOT_ALLOWED`
- `UNSAFE_INTEGER_NUMBER`
- `DUPLICATE_KEY`
- `INVALID_TIMESTAMP`
- `UNSUPPORTED_TYPE`
- `KEY_RESOLUTION_FAILED` (if post-normalization lookup cannot resolve)

Additional runtime-specific errors MUST NOT leak implementation details and MUST result in failure.

### 7.1 Common invalid cases → required error codes

| Invalid input                                   | Error code              |
|-------------------------------------------------|-------------------------|
| Any float / NaN / ±Inf                          | `FLOAT_NOT_ALLOWED`     |
| Integer outside safe range                      | `UNSAFE_INTEGER_NUMBER` |
| Duplicate key after NFC normalization           | `DUPLICATE_KEY`         |
| Key `ts` with non-integer / unsafe value        | `INVALID_TIMESTAMP`     |
| Unsupported runtime type (function/symbol/etc.) | `UNSUPPORTED_TYPE`      |

---

## 6. Allowed Types

The following types are allowed:

- object
- array
- string
- integer
- boolean
- null

---

## 7. Forbidden Types

The following MUST cause canonicalization failure:

- floating-point numbers
- NaN
- Infinity
- undefined
- functions
- binary values
- Map / Set
- Date objects
- custom class instances
- language-specific objects

---

## 8. Integer Rules

Integers MAY be represented as JSON numbers only if within:

[-(2^53 - 1), +(2^53 - 1)]

i.e.:

[-9007199254740991, 9007199254740991]

Otherwise they MUST be encoded as strings.

### Allowed

```json
{"count": 42}
{"count": "9007199254740993"}
