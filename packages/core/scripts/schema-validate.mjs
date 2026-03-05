import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dir = new URL("../schemas", import.meta.url).pathname;
const files = readdirSync(dir)
  .filter((f) => f.endsWith(".schema.json"))
  .filter((f) => f !== "api-extractor.schema.json")
  .sort();

let failed = false;
for (const file of files) {
  const full = join(dir, file);
  const raw = readFileSync(full, "utf8");
  let json;
  try {
    json = JSON.parse(raw);
  } catch (error) {
    failed = true;
    console.error(`FAIL ${file}: invalid JSON (${error.message})`);
    continue;
  }

  for (const key of ["$id", "title", "description"]) {
    if (typeof json[key] !== "string" || json[key].length === 0) {
      failed = true;
      console.error(`FAIL ${file}: missing/invalid ${key}`);
    }
  }
}

if (failed) {
  process.exit(1);
}
console.log(`OK schema metadata validated (${files.length} files)`);
