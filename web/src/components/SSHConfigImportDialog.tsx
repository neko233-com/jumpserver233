import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { selectedOrganization } from "../auth/organization";
import type { AccountChoice } from "./managedAccounts";
import "./ssh-config-import.css";

type Asset = { name: string; protocol?: string; accounts?: AccountChoice[] };
type FileHandle = {
  name: string;
  getFile: () => Promise<File>;
  createWritable: () => Promise<{ write: (data: string) => Promise<void>; close: () => Promise<void>; abort: () => Promise<void> }>;
};
type PickerWindow = Window & { showOpenFilePicker?: (options: { multiple: boolean }) => Promise<FileHandle[]> };
type Props = { request: (url: string, init?: RequestInit) => Promise<Response>; onClose: () => void };

const validName = /^[A-Za-z0-9_.-]+$/;
const markerPrefix = "# JumpServer233 managed SSH aliases: ";

async function prepareConfig(old: string, endpoint: string, host: string, port: number, username: string, organization: string, assets: Asset[]) {
  if (!validName.test(username) || !/^[A-Za-z0-9_.:-]+$/.test(host) || host.startsWith("-") || !Number.isInteger(port) || port < 1 || port > 65535 || !validName.test(organization)) throw new Error("invalid input");
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${endpoint}\0${host}\0${port}\0${username}\0${organization}`));
  const profile = Array.from(new Uint8Array(hash).slice(0, 6), (byte) => byte.toString(16).padStart(2, "0")).join("");
  const marker = markerPrefix + profile, begin = `# BEGIN ${marker}\n`, end = `# END ${marker}\n`;
  const entries: { alias: string; id: string; name: string }[] = [];
  const seen = new Set<string>();
  for (const asset of assets) {
    if (asset.protocol && asset.protocol !== "ssh") continue;
    for (const account of asset.accounts || []) {
      if (!account.active || !account.permissions.includes("connect")) continue;
      if (!/^[A-Za-z0-9_-]{1,128}$/.test(account.id) || seen.has(account.id)) throw new Error("invalid account");
      seen.add(account.id);
      const name = Array.from(`${asset.name} / ${account.name}`, (char) => char.codePointAt(0)! < 32 || char.codePointAt(0) === 127 ? " " : char).join("").slice(0, 160);
      entries.push({ alias: `jms-${profile}-${account.id}`, id: account.id, name });
    }
  }
  if (!entries.length) throw new Error("empty inventory");
  entries.sort((a, b) => a.alias.localeCompare(b.alias));
  const count = (text: string, fragment: string) => text.split(fragment).length - 1;
  const beginCount = count(old, begin), endCount = count(old, end);
  if (beginCount !== endCount || beginCount > 1 || (!beginCount && old.includes(marker))) throw new Error("invalid managed block");
  let rest = old;
  if (beginCount) {
    const start = old.indexOf(begin), finish = old.indexOf(end);
    if (finish < start) throw new Error("invalid managed block");
    rest = old.slice(0, start) + old.slice(finish + end.length);
  }
  for (const line of rest.split("\n")) {
    const fields = line.trim().split(/\s+/);
    if (fields[0]?.toLowerCase() !== "host") continue;
    for (const pattern of fields.slice(1)) {
      if (pattern === "*" || pattern.startsWith("!")) continue;
      const expression = "^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$";
      if (entries.some((entry) => new RegExp(expression, "i").test(entry.alias))) throw new Error("alias conflict");
    }
  }
  const block = begin + "# Generated from authorized inventory; no target credentials are stored.\n" + entries.map((entry) => `\n# ${entry.name}\nHost ${entry.alias}\n    HostName ${host}\n    Port ${port}\n    User ${username}#${entry.id}%${organization}\n`).join("") + end;
  const bom = rest.startsWith("\ufeff") ? "\ufeff" : "";
  if (bom) rest = rest.slice(1);
  return { contents: bom + block + rest, entries };
}

export default function SSHConfigImportDialog({ request, onClose }: Props) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const [host, setHost] = useState(window.location.hostname);
  const [port, setPort] = useState("2222");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [aliases, setAliases] = useState<string[]>([]);
  const supported = window.isSecureContext && typeof (window as PickerWindow).showOpenFilePicker === "function" && !!crypto.subtle;
  const safeHost = /^[A-Za-z0-9_.:-]+$/.test(host) && !host.startsWith("-");
  const safePort = /^\d{1,5}$/.test(port) && Number(port) > 0 && Number(port) <= 65535;
  useEffect(() => { const element = dialog.current; element?.showModal(); return () => element?.close(); }, []);

  async function importConfig() {
    const picker = (window as PickerWindow).showOpenFilePicker;
    if (!picker || busy) return;
    setBusy(true); setMessage(""); setAliases([]);
    try {
      // The picker must run in the click gesture; it never selects a file automatically.
      const [handle] = await picker({ multiple: false });
      if (!handle || handle.name !== "config") throw new Error("wrong file");
      const before = await handle.getFile();
      if (before.size > 4 * 1024 * 1024) throw new Error("file too large");
      const original = await before.text();
      const [identity, inventory] = await Promise.all([request("/api/v1/users/me"), request("/api/v1/assets")]);
      if (!identity.ok || !inventory.ok) throw new Error("inventory unavailable");
      const user = await identity.json() as { username: string };
      const assets = await inventory.json() as Asset[];
      const prepared = await prepareConfig(original, window.location.origin, host.trim(), Number(port), user.username, selectedOrganization(), assets);
      const latest = await handle.getFile();
      if (latest.size !== before.size || latest.lastModified !== before.lastModified || await latest.text() !== original) throw new Error("concurrent edit");
      const writable = await handle.createWritable();
      try { await writable.write(prepared.contents); await writable.close(); } catch (error) { await writable.abort(); throw error; }
      setMessage(t("sshConfigImport.success", { count: prepared.entries.length }));
      setAliases(prepared.entries.map((entry) => `${entry.alias}  ${entry.name}`));
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
      setMessage(t("sshConfigImport.failed"));
    } finally { setBusy(false); }
  }

  return <dialog ref={dialog} className="asset-modal ssh-config-import" aria-labelledby="ssh-config-title" onCancel={(event) => { event.preventDefault(); onClose(); }}>
    <h2 id="ssh-config-title">{t("sshConfigImport.title")}</h2>
    <p>{t("sshConfigImport.hint")}</p>
    <label>{t("sshConfigImport.host")}<input value={host} onChange={(event) => setHost(event.target.value)} /></label>
    <label>{t("sshConfigImport.port")}<input type="number" min="1" max="65535" value={port} onChange={(event) => setPort(event.target.value)} /></label>
    {supported ? <p>{t("sshConfigImport.chooseFile")}</p> : <><p>{t("sshConfigImport.fallback")}</p>{safeHost && safePort && <><p>{t("sshConfigImport.windows")}</p><pre>{`$env:JMS_SERVER_URL='${window.location.origin}'\njms ssh-config sync --host ${host} --port ${port}`}</pre><p>{t("sshConfigImport.unix")}</p><pre>{`JMS_SERVER_URL='${window.location.origin}' jms ssh-config sync --host ${host} --port ${port}`}</pre></>}</>}
    {message && <p role="status">{message}</p>}
    {aliases.length > 0 && <pre>{aliases.join("\n")}</pre>}
    <div className="asset-modal-actions"><button type="button" onClick={onClose}>{t("sshConfigImport.close")}</button>{supported && <button type="button" className="button-primary" disabled={busy || !safeHost || !safePort} onClick={() => void importConfig()}>{t("sshConfigImport.import")}</button>}</div>
  </dialog>;
}
