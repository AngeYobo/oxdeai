#!/usr/bin/env tsx
import { main } from "./index.js";

main(process.argv.slice(2)).then((code) => process.exit(code)).catch((err) => {
  console.error("[bench] failed");
  console.error(err);
  process.exit(1);
});
