import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

type OkVector = {
  id: string;
  description: string;
  status: "ok";
  input: unknown;
  expected_canonical_json: string;
  expected_sha256: string;
};

type ErrorVector = {
  id: string;
  description: string;
  status: "error";
  input: unknown;
  expected_error: string;
};

type Vector = OkVector | ErrorVector;

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function normalizeString(value: string): string {
  return value.normalize("NFC");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function sortUtf8Lex(keys: string[]): string[] {
  return [...keys].sort((a, b) =>
    Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"))
  );
}

function canonicalize(input: unknown): Uint8Array {
  return Buffer.from(canonicalizeToJson(input), "utf8");
}

function canonicalizeToJson(value: unknown): string {
  if (value === null) {
    return "null";
  }

  if (typeof value === "string") {
    return JSON.stringify(normalizeString(value));
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error("FLOAT_NOT_ALLOWED");
    }
    if (!Number.isSafeInteger(value)) {
      throw new Error("UNSAFE_INTEGER_NUMBER");
    }
    return String(value);
  }

  if (typeof value === "bigint") {
    return JSON.stringify(String(value));
  }

  if (
    typeof value === "undefined" ||
    typeof value === "function" ||
    typeof value === "symbol"
  ) {
    throw new Error("UNSUPPORTED_TYPE");
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeToJson(item)).join(",")}]`;
  }

  if (isPlainObject(value)) {
    const normalizedEntries = Object.entries(value).map(([k, v]) => {
      return [normalizeString(k), v] as const;
    });

    const seen = new Set<string>();
    for (const [k] of normalizedEntries) {
      if (seen.has(k)) {
        throw new Error("DUPLICATE_KEY");
      }
      seen.add(k);
    }

    const sortedKeys = sortUtf8Lex(normalizedEntries.map(([k]) => k));

    const parts = sortedKeys.map((key) => {
      const entry = normalizedEntries.find(([k]) => k === key);
      if (!entry) {
        throw new Error("KEY_RESOLUTION_FAILED");
      }

      const [, child] = entry;

      // Profile-specific validation retained from your current code.
      if (key === "ts") {
        if (
          typeof child !== "number" ||
          !Number.isInteger(child) ||
          !Number.isSafeInteger(child)
        ) {
          throw new Error("INVALID_TIMESTAMP");
        }
      }

      return `${JSON.stringify(key)}:${canonicalizeToJson(child)}`;
    });

    return `{${parts.join(",")}}`;
  }

  throw new Error("UNSUPPORTED_TYPE");
}

function getVectorsFilePath(): string {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);

  return resolve(
    __dirname,
    "../docs/spec/test-vectors/canonicalization-v1.json"
  );
}

function loadVectors(): Vector[] {
  const file = getVectorsFilePath();
  return JSON.parse(readFileSync(file, "utf8")) as Vector[];
}

function saveVectors(vectors: Vector[]): void {
  const file = getVectorsFilePath();
  writeFileSync(file, JSON.stringify(vectors, null, 2) + "\n", "utf8");
}

function main(): void {
  const vectors = loadVectors();

  const updated: Vector[] = vectors.map((vector) => {
    if (vector.status === "error") {
      return vector;
    }

    const bytes = canonicalize(vector.input);
    const canonicalJson = Buffer.from(bytes).toString("utf8");
    const hash = sha256Hex(bytes);

    return {
      ...vector,
      expected_canonical_json: canonicalJson,
      expected_sha256: hash,
    };
  });

  saveVectors(updated);
  console.log(`Updated ${updated.length} vector(s)`);
}

main();