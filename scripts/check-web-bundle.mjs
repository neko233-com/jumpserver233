// Inspect the production graph, including shared imports, without hiding chunks
// behind a raised warning limit. Login animation stays outside the console entry.
import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const root = new URL("../web/dist/", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL(".vite/manifest.json", root), "utf8"));
const initial = new Set();
function visit(key) {
  if (initial.has(key)) return;
  const chunk = manifest[key];
  if (!chunk) throw new Error(`Missing production import: ${key}`);
  initial.add(key);
  for (const dependency of chunk.imports ?? []) visit(dependency);
}
visit("index.html");
const files = [...new Set(Object.values(manifest).map((chunk) => chunk.file))].filter((file) => file.endsWith(".js"));
let total = 0, largest = 0, initialBytes = 0, initialGzip = 0;
for (const file of files) {
  const bytes = statSync(fileURLToPath(new URL(file, root))).size;
  total += bytes;
  largest = Math.max(largest, bytes);
}
for (const key of initial) {
  const raw = readFileSync(new URL(manifest[key].file, root));
  initialBytes += raw.length;
  initialGzip += gzipSync(raw).length;
}
const login = "src/pages/LoginPage.tsx";
if (!manifest[login]?.isDynamicEntry || initial.has(login)) throw new Error("Login code must remain a lazy route");
const risks = "src/pages/AccountRisksPage.tsx";
if (!manifest[risks]?.isDynamicEntry || initial.has(risks)) throw new Error("Account risk UI and feature locales must remain a lazy route");
const rotation="src/pages/RotationPlansPage.tsx";
if(!manifest[rotation]?.isDynamicEntry || initial.has(rotation)) throw new Error("Credential rotation UI and feature locales must remain a lazy route");
for (const entry of ["src/pages/PasswordChangePage.tsx", "src/components/PasswordSecuritySettings.tsx"]) {
  if (!manifest[entry]?.isDynamicEntry || initial.has(entry)) throw new Error("Password security screens must remain lazy");
}
// Allocate 25 kB for required password security screens and shared resources.
// Keep counting every chunk and retain the existing initial/single-chunk limits.
if (largest > 500_000 || initialBytes > 500_000 || total > 1_525_000) throw new Error("Production JavaScript exceeds the recorded size budget");
console.log(JSON.stringify({ initialJavaScriptBytes: initialBytes, initialGzipBytes: initialGzip, totalJavaScriptBytes: total, largestChunkBytes: largest, lazyLogin: true }));
