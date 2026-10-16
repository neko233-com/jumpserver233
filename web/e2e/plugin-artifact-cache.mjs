import { copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";

// Reuse only public release artifacts. Production Cache.Fetch still verifies
// every archive hash and extracts the pinned entry before remote installation.
export function stagePluginArtifacts(source, target) {
  if (!existsSync(source)) return 0;
  if (!lstatSync(source).isDirectory() || lstatSync(source).isSymbolicLink())
    throw new Error("Plugin artifact cache must be a regular directory");
  if (existsSync(target) && (!lstatSync(target).isDirectory() || lstatSync(target).isSymbolicLink()))
    throw new Error("Plugin artifact target must be a regular directory");
  let files = 0, bytes = 0, directories = 0;
  for (const dir of readdirSync(source, { withFileTypes: true })) {
    if (!/^[a-f0-9]{64}$/.test(dir.name) || !dir.isDirectory() || dir.isSymbolicLink()) continue;
    if (++directories > 32) throw new Error("Plugin artifact cache capacity exceeded");
    for (const name of ["artifact", "executable"]) {
      const from = join(source, dir.name, name);
      if (!existsSync(from)) continue;
      const info = lstatSync(from);
      if (!info.isFile() || info.isSymbolicLink()) continue;
      if (info.size < 1 || info.size > 64 * 1024 * 1024 || (bytes += info.size) > 512 * 1024 * 1024)
        throw new Error("Plugin artifact cache size exceeded");
      const to = join(target, dir.name);
      mkdirSync(to, { recursive: true, mode: 0o700 });
      if (lstatSync(to).isSymbolicLink()) throw new Error("Plugin artifact destination cannot be a link");
      const output = join(to, name);
      if (existsSync(output) && (!lstatSync(output).isFile() || lstatSync(output).isSymbolicLink()))
        throw new Error("Plugin artifact destination must be a regular file");
      copyFileSync(from, output);
      files++;
    }
  }
  return files;
}
