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