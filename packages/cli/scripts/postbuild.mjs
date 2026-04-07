// SPDX-License-Identifier: Apache-2.0
import { chmod, readFile, writeFile } from "node:fs/promises";

const entrypoint = new URL("../dist/main.js", import.meta.url);
const shebang = "#!/usr/bin/env node\n";
const content = await readFile(entrypoint, "utf8");

if (!content.startsWith(shebang)) {
  await writeFile(entrypoint, shebang + content, "utf8");
}

await chmod(entrypoint, 0o755);
