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
for (const page of ["AssistantPage", "PAMPage", "AssetDiscoveryPage", "BrandingPage", "IdentitySourcesPage", "DirectorySyncPage", "EnterpriseLoginSettingsPage", "SMSMFASettingsPage", "ReplayStoragePage", "DatabaseAuditPage", "OrganizationOverviewPage", "OIDCSettingsPage", "LDAPSettingsPage", "SAMLSettingsPage", "CASSettingsPage", "RadiusSettingsPage", "AnnouncementsPage"]) {
  if (manifest[`src/pages/${page}.tsx`]) throw new Error(`Deferred enterprise page is in the mini production graph: ${page}`);
}
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
const updates="src/components/UpdateSettings.tsx";
if(!manifest[updates]?.isDynamicEntry||initial.has(updates))throw new Error("Update settings and bilingual release information must remain lazy");
// Count every shipped mini chunk. Preserve the existing total, initial and
// individual-chunk limits; removing deferred routes must not raise the budget.
if (largest > 500_000 || initialBytes > 500_000 || total > 1_661_200) throw new Error("Production JavaScript exceeds the recorded size budget");
console.log(JSON.stringify({ initialJavaScriptBytes: initialBytes, initialGzipBytes: initialGzip, totalJavaScriptBytes: total, largestChunkBytes: largest, lazyLogin: true }));
