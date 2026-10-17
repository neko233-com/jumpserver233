import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const errors = [];

function flatten(value, prefix = "", result = new Map()) {
  for (const [key, entry] of Object.entries(value)) {
    const path = prefix + key;
    if (typeof entry === "string") result.set(path, entry);
    else if (entry && typeof entry === "object")
      flatten(entry, path + ".", result);
    else errors.push(`Invalid translation value: ${path}`);
  }
  return result;
}

const locales = await Promise.all(
  ["en", "zh-CN"].map(async (name) => {
    const result=flatten((await import(pathToFileURL(resolve(root, `web/src/i18n/locales/${name}.ts`)))).default);
    const featureRoot=resolve(root,"web/src/i18n/locales/features");
    if(existsSync(featureRoot))for(const feature of readdirSync(featureRoot)){
      const path=resolve(featureRoot,feature,`${name}.ts`);
      if(!existsSync(path)){errors.push(`Missing feature locale: ${feature}/${name}`);continue}
      const values=flatten((await import(pathToFileURL(path))).default);
      for(const [key,value] of values){if(result.has(key))errors.push(`Duplicate translation key: ${key}`);result.set(key,value)}
    }
    return result;
  }),
);
const keys = [...locales[0].keys()].sort();
if (JSON.stringify(keys) !== JSON.stringify([...locales[1].keys()].sort()))
  errors.push("English and Chinese translation keys differ");
const placeholders = (value) => [...value.matchAll(/\{\{\s*([^}]+?)\s*\}\}/g)]
  .map((match) => match[1]).sort();
for (const key of keys) {
  if (!locales[1].has(key)) continue;
  if (JSON.stringify(placeholders(locales[0].get(key))) !==
      JSON.stringify(placeholders(locales[1].get(key))))
    errors.push(`Translation placeholders differ: ${key}`);
}

function walk(directory) {
  return readdirSync(directory).flatMap((name) => {
    const path = resolve(directory, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}
const documents = [
  "README.md", "README.en.md", "AGENTS.md", "AGENTS.zh.md",
  ...walk(resolve(root, "docs")).filter((path) => path.endsWith(".md"))
    .map((path) => relative(root, path)),
  "server/third_party/go-mssqldb/UPSTREAM.md",
  "server/third_party/go-mssqldb/UPSTREAM.en.md",
  "server/third_party/grdp/UPSTREAM.md",
  "server/third_party/grdp/UPSTREAM.en.md",
];
let links = 0;
for (const document of documents) {
  const path = resolve(root, document);
  const source = readFileSync(path, "utf8");
  const pair = document === "AGENTS.md" ? "AGENTS.zh.md" :
    document === "AGENTS.zh.md" ? "AGENTS.md" :
      document.endsWith(".en.md") ? document.replace(/\.en\.md$/, ".md") :
        document.replace(/\.md$/, ".en.md");
  if (!existsSync(resolve(root, pair))) errors.push(`Missing bilingual pair: ${document}`);
  if (!source.slice(0, 400).includes(pair.split(/[\\/]/).at(-1)))
    errors.push(`Missing opening language link: ${document}`);
  for (const match of source.matchAll(/\]\(([^)]+)\)/g)) {
    let target = match[1].split(/\s+"/)[0];
    if (/^(?:https?:|mailto:|#)/i.test(target)) continue;
    target = target.split("#")[0];
    if (!target) continue;
    links++;
    try { target = decodeURIComponent(target); } catch { /* Check the literal path. */ }
    if (!existsSync(resolve(dirname(path), target)))
      errors.push(`Missing relative link: ${document}: ${target}`);
  }
}

const driver = resolve(root, "server/third_party/go-mssqldb");
const manifest = readFileSync(resolve(driver, "UPSTREAM.sha256"), "utf8").replace(/^\uFEFF/, "");
const modified = [];
let originalFiles = 0;
for (const line of manifest.trim().split(/\r?\n/)) {
  const match = line.match(/^([a-f0-9]{64})\s+(.+)$/);
  if (!match) { errors.push("Invalid SQL Server upstream hash manifest"); continue; }
  originalFiles++;
  const path = resolve(driver, match[2]);
  if (!existsSync(path)) { errors.push(`Missing upstream file: ${match[2]}`); continue; }
  if (createHash("sha256").update(readFileSync(path)).digest("hex") !== match[1])
    modified.push(match[2]);
}
if (modified.sort().join(",") !== "mssql.go,types.go")
  errors.push(`Unexpected SQL Server driver patches: ${modified.join(", ")}`);

const rdpRuntime=resolve(root,"server/third_party/grdp");
const rdpManifest=readFileSync(resolve(rdpRuntime,"UPSTREAM.sha256"),"utf8");
const rdpModified=[]; let rdpOriginalFiles=0;
for(const line of rdpManifest.trim().split(/\r?\n/)){
 const match=line.match(/^([a-f0-9]{64})\s+(.+)$/);if(!match){errors.push("Invalid RDP upstream manifest");continue;}
 rdpOriginalFiles++;const path=resolve(rdpRuntime,match[2]);if(!existsSync(path)){errors.push(`Missing RDP upstream file: ${match[2]}`);continue;}
 if(createHash("sha256").update(readFileSync(path)).digest("hex")!==match[1])rdpModified.push(match[2]);
}
if(rdpModified.sort().join(",")!=="emission/emitter.go,protocol/pdu/pdu.go,protocol/sec/sec.go,protocol/t125/mcs.go")errors.push(`Unexpected RDP patches: ${rdpModified.join(", ")}`);
console.log(JSON.stringify({
  translationKeysPerLocale: keys.length, bilingualDocuments: documents.length,
  relativeLinks: links, originalDriverFiles: originalFiles,
  documentedDriverPatches: modified, rdpOriginalFiles, documentedRDPPatches:rdpModified, errors,
}, null, 2));
if (errors.length) process.exitCode = 1;
