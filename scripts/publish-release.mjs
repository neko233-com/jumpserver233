import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = "neko233-com/jumpserver233";
export function releaseFiles(tag) {
  if (!/^v(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})$/.test(tag)) throw new Error("A stable vX.Y.Z release is required");
  return ["linux", "darwin", "windows"].flatMap(os => ["amd64", "arm64"].flatMap(arch => {
    const name = `jumpserver233-${tag}-${os}-${arch}.tar.gz`;
    return [name, name + ".sha256"];
  }));
}
export function uploadPlan(release, tag, files) {
  if (release.tag_name !== tag || release.draft || release.prerelease || !release.published_at || release.html_url !== `https://github.com/${repository}/releases/tag/${tag}`) throw new Error("Only an existing official published stable release accepts artifacts");
  return files.map(file => {
    const found = release.assets.filter(a => a.name === file.name);
    if (found.length > 1) throw new Error("Duplicate release assets");
    if (found.length && (found[0].state !== "uploaded" || found[0].size !== file.bytes || found[0].digest !== `sha256:${file.sha256}`)) throw new Error("Existing release artifact differs; overwrite refused");
    return { ...file, action: found.length ? "unchanged" : "upload" };
  });
}
function main(args) {
  function option(name) { const index = args.indexOf(name); if (index < 0 || !args[index + 1] || args[index + 1].startsWith("--")) throw new Error("Use --tag vX.Y.Z --directory dist [--publish]"); const value = args[index + 1]; args.splice(index, 2); return value; }
  const tag = option("--tag"), folder = resolve(option("--directory")), publish = args.includes("--publish");
  if (publish) args.splice(args.indexOf("--publish"), 1);
  if (args.length) throw new Error("Unknown release publisher option");
  const files = releaseFiles(tag).map(name => {
    const path = resolve(folder, name), info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 256 * 1024 * 1024) throw new Error("Native artifact must be a regular bounded file");
    return { name, path, bytes: info.size, sha256: createHash("sha256").update(readFileSync(path)).digest("hex") };
  });
  for (const file of files.filter(f => f.name.endsWith(".sha256"))) {
    const archive = files.find(f => f.name === file.name.slice(0, -7));
    if (readFileSync(file.path, "utf8") !== `${archive.sha256}  ${archive.name}\n`) throw new Error("Archive checksum sidecar mismatch");
  }
  const inspect = () => JSON.parse(execFileSync("gh", ["api", "-H", "X-GitHub-Api-Version: 2026-03-10", `repos/${repository}/releases/tags/${tag}`], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  const plan = uploadPlan(inspect(), tag, files);
  for (const file of plan) {
    if (publish && file.action === "upload") {
      // No --clobber: a concurrent publication cannot replace existing bytes.
      execFileSync("gh", ["release", "upload", tag, file.path, "--repo", repository], { stdio: ["ignore", "pipe", "pipe"] });
      const [verified] = uploadPlan(inspect(), tag, [file]);
      if (verified.action !== "unchanged") throw new Error("Release asset readback failed");
    }
  }
  console.log(JSON.stringify({ published: publish, files: plan.map(({ name, action }) => ({ name, action })) }));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch { process.stderr.write("Native release publication failed; existing assets were not overwritten.\n"); process.exitCode = 1; }
}
