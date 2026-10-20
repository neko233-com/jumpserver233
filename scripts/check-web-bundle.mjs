// Inspect the production graph, including shared imports, without hiding chunks
// behind a raised warning limit. Login animation stays outside the console entry.
import { readFileSync, statSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { resolve, sep } from "node:path";
import { gzipSync } from "node:zlib";

const args=process.argv.slice(2);
if(args.length && (args.length!==2||args[0]!=="--dir"||!args[1]))throw new Error("Use [--dir PRODUCTION_OUTPUT]");
const output = args.length ? args[1] : process.env.JMS_E2E_WEB_DIR;
const root = output ? pathToFileURL(resolve(output)+sep) : new URL("../web/dist/", import.meta.url);
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
const assistant = "src/pages/AssistantPage.tsx";
const pam = "src/pages/PAMPage.tsx";
if (!manifest[pam]?.isDynamicEntry || initial.has(pam)) throw new Error("PAM management and feature locales must remain lazy");
if (!manifest[assistant]?.isDynamicEntry || initial.has(assistant)) throw new Error("AI assistant and its feature locales must remain a lazy route");
if (!manifest[login]?.isDynamicEntry || initial.has(login)) throw new Error("Login code must remain a lazy route");
const risks = "src/pages/AccountRisksPage.tsx";
if (!manifest[risks]?.isDynamicEntry || initial.has(risks)) throw new Error("Account risk UI and feature locales must remain a lazy route");
const rotation="src/pages/RotationPlansPage.tsx";
if(!manifest[rotation]?.isDynamicEntry || initial.has(rotation)) throw new Error("Credential rotation UI and feature locales must remain a lazy route");
for (const entry of ["src/pages/PasswordChangePage.tsx", "src/components/PasswordSecuritySettings.tsx"]) {
  if (!manifest[entry]?.isDynamicEntry || initial.has(entry)) throw new Error("Password security screens must remain lazy");
}
const history = "src/components/MonitorHistoryDialog.tsx";
if (!manifest[history]?.isDynamicEntry || initial.has(history)) throw new Error("Monitoring history charts and feature locales must remain lazy");
const branding="src/pages/BrandingPage.tsx";
if(!manifest[branding]?.isDynamicEntry||initial.has(branding))throw new Error("Branding management and feature locales must remain lazy");
const discovery="src/pages/AssetDiscoveryPage.tsx";
if(!manifest[discovery]?.isDynamicEntry||initial.has(discovery))throw new Error("Asset discovery and its bilingual resources must remain lazy");
const updates="src/components/UpdateSettings.tsx";
if(!manifest[updates]?.isDynamicEntry||initial.has(updates))throw new Error("Update settings and bilingual release information must remain lazy");
// Allocate 25 kB for required password security screens and shared resources.
// Keep counting every chunk and retain the existing initial/single-chunk limits.
// Allocate 20 kB for global branding bootstrap, safe image/appearance controls,
// bilingual editor and audit. Preserve the initial and individual chunk limits.
// LAN discovery adds 40,444 measured bytes for editors, scans, one-use import,
// audit and both lazy locales. Allocate 42 kB; retain 500 kB entry/chunk limits.
// AWS source controls and both lazy locales add 5,738 measured bytes. Allocate
// 6 kB while keeping the unchanged 500 kB initial/single-chunk limits.
// Stable-release controls and both lazy locales add approximately 8.6 kB.
// Allocate 9 kB for the required feature; initial/single-chunk limits stay fixed.
// Verified execution-directory controls, review metadata, terminal notices and
// both lazy locales add 4,045 measured bytes. Allocate 4.2 kB without changing
// the initial/single-chunk limits or adding frontend dependencies.
// Standalone drain UI and both lazy locales receive a 9 kB feature allowance.
// Keep the 500 kB entry and individual-chunk limits unchanged.
// Revision-bound scheduled installation controls and lazy bilingual guidance.
// Allocate 12 kB; preserve the initial and individual chunk caps.
// Opt-in automatic release policy controls and lazy bilingual guidance.
// Allocate 10 kB while retaining the initial and individual chunk caps.
// Organization SSH generation policy and both lazy locales: 8 kB allowance.
// Write-only fixed-password controls, save nonces and both lazy locales: 8 kB.
// Batch/template/Playbook directory snapshots and bilingual controls: 4 kB.
if (largest > 500_000 || initialBytes > 500_000 || total > 1_661_200) throw new Error("Production JavaScript exceeds the recorded size budget");
console.log(JSON.stringify({ initialJavaScriptBytes: initialBytes, initialGzipBytes: initialGzip, totalJavaScriptBytes: total, largestChunkBytes: largest, lazyLogin: true }));
