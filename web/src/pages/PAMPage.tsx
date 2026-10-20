import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/pam/register";
import "./PAMPage.css";

type Principal = {
  username: string;
  host?: string;
  principal_id: string;
  scope: string;
  auth_plugin?: string;
  enabled: boolean;
};
type PAM = { platform: string; enabled: boolean; principal: Principal };
type Asset = { id: string; name: string; username: string; protocol?: string; pam?: PAM };
type Account = {
  id: string;
  username: string;
  name: string;
  version: string;
  default: boolean;
  pam?: PAM;
  credential_type: string;
  password_rotation_enabled: boolean;
  password_rotation?: { state: string };
};
type Discovery = { version: string; platform: string; principals: Principal[] };
type Input = {
  principal: Principal;
  version: string;
  update: boolean;
  name?: string;
  password?: string;
  automatic: boolean;
  request_id: string;
  preview_token?: string;
};
type Preview = {
  preview_token?: string;
  committed: boolean;
  issues: { code: string }[];
  rows: { account_id: string; username: string; action: string }[];
};
const nonce = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (v) =>
    v.toString(16).padStart(2, "0"),
  ).join("");
const supported = new Set(["ssh", "postgresql", "mysql", "mariadb", "sqlserver"]);
export default function PAMPage() {
  const { t } = useTranslation(),
    { accessToken } = useAuth(),
    { allows, ready } = usePermissions();
  const viewAll = allows("assets.view_all"),
    collect = viewAll && allows("accounts.discover"),
    manage = viewAll && allows("accounts.manage") && allows("assets.rotate"),
    enroll = manage && collect && allows("accounts.import");
  const allowed = viewAll && (collect || manage || allows("accounts.rotation.view"));
  const [assets, setAssets] = useState<Asset[]>([]),
    [selected, setSelected] = useState(""),
    [accounts, setAccounts] = useState<Account[]>([]),
    [accountTotal, setAccountTotal] = useState(0),
    [accountOffset, setAccountOffset] = useState(0);
  const [discovery, setDiscovery] = useState<Discovery | null>(null),
    [query, setQuery] = useState(""),
    [offset, setOffset] = useState(0),
    [principal, setPrincipal] = useState<Principal | null>(null),
    [existing, setExisting] = useState<Account | null>(null),
    [name, setName] = useState(""),
    [password, setPassword] = useState(""),
    [automatic, setAutomatic] = useState(false),
    [preview, setPreview] = useState<Preview | null>(null);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [status, setStatus] = useState("");
  const flow = useRef<AbortController | null>(null),
    generation = useRef(0),
    assetReads = useRef(0),
    accountReads = useRef(0),
    pending = useRef<{ hash: string; input: Input } | null>(null),
    platformReceipt = useRef<{
      key: string;
      input: { platform: string; version: string; request_id: string };
    } | null>(null);
  const request = useCallback(
    async (path: string, method = "GET", body?: unknown, signal?: AbortSignal) => {
      const response = await fetch("/api/v1/" + path, {
        method,
        credentials: "same-origin",
        signal,
        headers: {
          ...(accessToken ? { Authorization: "Bearer " + accessToken } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!response.ok) {
        const v = await response.json().catch(() => ({}));
        throw Error(v.error_code ?? "pam_unavailable");
      }
      return response.status === 204 ? null : response.json();
    },
    [accessToken],
  );
  const problem = (e: unknown) => setError(e instanceof Error ? e.message : "pam_unavailable");
  const loadAssets = useCallback(
    async (signal?: AbortSignal) => {
      const read = ++assetReads.current;
      const rows = await request("assets", "GET", undefined, signal);
      if (!signal?.aborted && read === assetReads.current)
        setAssets(rows.filter((a: Asset) => supported.has(a.protocol || "ssh")));
    },
    [request],
  );
  const loadAccounts = useCallback(
    async (signal?: AbortSignal) => {
      if (!selected) return;
      const read = ++accountReads.current;
      const rows = await request(
        `assets/${selected}/accounts?offset=${accountOffset}&limit=20`,
        "GET",
        undefined,
        signal,
      );
      if (!signal?.aborted && read === accountReads.current) {
        setAccounts(rows.results);
        setAccountTotal(rows.total);
      }
    },
    [request, selected, accountOffset],
  );
  useEffect(() => {
    if (!ready || !allowed) return;
    const c = new AbortController();
    void loadAssets(c.signal).catch((e) => {
      if (!c.signal.aborted) problem(e);
    });
    return () => c.abort();
  }, [ready, allowed, loadAssets]);
  useEffect(() => {
    if (!ready || !allowed || !selected) return;
    const c = new AbortController();
    void loadAccounts(c.signal).catch((e) => {
      if (!c.signal.aborted) problem(e);
    });
    return () => c.abort();
  }, [ready, allowed, selected, loadAccounts]);
  useEffect(
    () => () => {
      generation.current++;
      flow.current?.abort();
    },
    [],
  );
  const resetDraft = () => {
    setPrincipal(null);
    setExisting(null);
    setPassword("");
    setPreview(null);
    pending.current = null;
    setAutomatic(false);
  };
  const changeAsset = (id: string) => {
    generation.current++;
    flow.current?.abort();
    platformReceipt.current = null;
    setBusy(false);
    setSelected(id);
    setAccountOffset(0);
    setAccounts([]);
    setDiscovery(null);
    setQuery("");
    setOffset(0);
    setError("");
    setStatus("");
    resetDraft();
  };
  const source = assets.find((a) => a.id === selected),
    windows = source?.pam?.platform === "windows",
    ssh = !source?.protocol || source.protocol === "ssh";
  const configure = async (platform: string) => {
    if (!selected || busy) return;
    setBusy(true);
    setError("");
    const version = generation.current,
      c = new AbortController();
    flow.current = c;
    try {
      const key = selected + ":" + platform;
      if (platformReceipt.current?.key !== key) {
        const rows = await request(
          `assets/${selected}/accounts?offset=0&limit=1`,
          "GET",
          undefined,
          c.signal,
        );
        const current = rows.results[0];
        if (!current?.default) throw Error("pam_conflict");
        platformReceipt.current = {
          key,
          input: { platform, version: current.version, request_id: nonce() },
        };
      }
      await request(
        `assets/${selected}/pam/platform`,
        "PUT",
        platformReceipt.current.input,
        c.signal,
      );
      if (version === generation.current) {
        platformReceipt.current = null;
        await Promise.all([loadAssets(c.signal), loadAccounts(c.signal)]);
        setStatus("configured");
        setDiscovery(null);
        resetDraft();
      }
    } catch (e) {
      if (e instanceof Error && e.message === "pam_conflict") platformReceipt.current = null;
      if (!c.signal.aborted) problem(e);
    } finally {
      if (version === generation.current) setBusy(false);
    }
  };
  const scan = async () => {
    if (!selected || busy) return;
    setBusy(true);
    setError("");
    setStatus("");
    resetDraft();
    const version = generation.current,
      c = new AbortController();
    flow.current = c;
    try {
      const rows = await request(
        `assets/${selected}/pam/principals`,
        "GET",
        undefined,
        AbortSignal.any([c.signal, AbortSignal.timeout(22000)]),
      );
      if (version === generation.current) {
        setDiscovery(rows);
        setQuery("");
        setOffset(0);
        setStatus("collected");
      }
    } catch (e) {
      if (!c.signal.aborted) problem(e);
    } finally {
      if (version === generation.current) setBusy(false);
    }
  };
  const choose = async (p: Principal) => {
    if (busy) return;
    const version = generation.current,
      c = new AbortController();
    flow.current?.abort();
    flow.current = c;
    setBusy(true);
    setError("");
    resetDraft();
    try {
      const data = await request(
        `assets/${selected}/accounts?username=${encodeURIComponent(p.username)}${p.host ? "&account_host=" + encodeURIComponent(p.host) : ""}&offset=0&limit=100`,
        "GET",
        undefined,
        c.signal,
      );
      const matches: Account[] = data.results;
      const found =
        matches.find((a) => a.pam?.principal.host === (p.host ?? "")) ??
        matches.find((a) => !a.pam?.principal.host);
      if (version === generation.current) {
        setPrincipal(p);
        setExisting(found ?? null);
        setName(found?.name ?? p.username + (p.host ? "@" + p.host : ""));
        setAutomatic(found?.pam?.enabled ? found.password_rotation_enabled : false);
      }
    } catch (e) {
      if (!c.signal.aborted) problem(e);
    } finally {
      if (version === generation.current) setBusy(false);
    }
  };
  const makePreview = async (e: FormEvent) => {
    e.preventDefault();
    if (!principal || !discovery || busy) return;
    setBusy(true);
    setError("");
    const version = generation.current,
      c = new AbortController();
    flow.current = c;
    const input = {
      principal,
      version: existing?.version ?? discovery.version,
      update: !!existing,
      name,
      password,
      automatic,
    };
    const hash = JSON.stringify(input);
    if (pending.current?.hash !== hash)
      pending.current = { hash, input: { ...input, request_id: nonce() } };
    try {
      const result: Preview = await request(
        `assets/${selected}/pam/import-preview`,
        "POST",
        pending.current.input,
        c.signal,
      );
      if (version !== generation.current) return;
      if (result.issues.length || !result.preview_token) throw Error("pam_invalid");
      pending.current.input.preview_token = result.preview_token;
      setPreview(result);
    } catch (e) {
      if (!c.signal.aborted) problem(e);
    } finally {
      if (version === generation.current) setBusy(false);
    }
  };
  const commit = async () => {
    if (!pending.current?.input.preview_token || busy) return;
    setBusy(true);
    setError("");
    const version = generation.current,
      c = new AbortController();
    flow.current = c;
    try {
      await request(
        `assets/${selected}/pam/import-commit`,
        "POST",
        pending.current.input,
        c.signal,
      );
      if (version === generation.current) {
        resetDraft();
        await Promise.all([loadAccounts(c.signal), loadAssets(c.signal)]);
        setStatus("enrolled");
      }
    } catch (e) {
      if (!c.signal.aborted) problem(e);
    } finally {
      if (version === generation.current) setBusy(false);
    }
  };
  if (!ready) return null;
  if (!allowed) return <p role="alert">{t("pam.denied")}</p>;
  const filtered =
    discovery?.principals.filter((p) =>
      (p.username + " " + (p.host ?? "") + " " + p.principal_id)
        .toLocaleLowerCase()
        .includes(query.toLocaleLowerCase()),
    ) ?? [];
  const errorKey = [
    "pam_invalid",
    "pam_denied",
    "pam_conflict",
    "pam_not_found",
    "pam_scope",
    "pam_busy",
  ].includes(error)
    ? error
    : "pam_unavailable";
  return (
    <section className="pam-page">
      <header>
        <h1>{t("pam.title")}</h1>
        <p>{t("pam.description")}</p>
        <Link to="/console/rotation-plans">{t("pam.plans")}</Link>
      </header>
      {error && <p role="alert">{t("pam.errors." + errorKey)}</p>}
      {status && <p role="status">{t("pam.status." + status)}</p>}
      <label className="pam-picker">
        {t("pam.asset")}
        <select value={selected} disabled={busy} onChange={(e) => changeAsset(e.target.value)}>
          <option value="">{t("pam.selectAsset")}</option>
          {assets.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name} · {a.username} · {t("pam.protocols." + (a.protocol || "ssh"))}
            </option>
          ))}
        </select>
      </label>
      {selected && (
        <>
          <div className="pam-actions">
            {ssh && manage && !windows && (
              <button type="button" disabled={busy} onClick={() => void configure("windows")}>
                {t("pam.windows")}
              </button>
            )}
            {ssh && manage && windows && !source?.pam?.enabled && (
              <button type="button" disabled={busy} onClick={() => void configure("linux")}>
                {t("pam.linux")}
              </button>
            )}
            {collect && (
              <button
                type="button"
                disabled={busy || (ssh && !windows)}
                onClick={() => void scan()}
              >
                {t(busy ? "pam.working" : "pam.collect")}
              </button>
            )}
          </div>
          {ssh && !windows && <p>{t("pam.windowsHelp")}</p>}
          <h2>{t("pam.managed")}</h2>
          <div className="pam-table">
            <table>
              <thead>
                <tr>
                  {["account", "identity", "rotation"].map((k) => (
                    <th key={k} scope="col">
                      {t("pam." + k)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {accounts.map((a) => (
                  <tr key={a.id}>
                    <td>
                      {a.name} · {a.username}
                      {a.pam?.principal.host ? "@" + a.pam.principal.host : ""}
                    </td>
                    <td>{a.pam?.principal.principal_id ?? t("pam.unpinned")}</td>
                    <td>{t("pam.states." + (a.password_rotation?.state ?? "disabled"))}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pam-pages">
            <button
              type="button"
              disabled={!accountOffset || busy}
              onClick={() => setAccountOffset(Math.max(0, accountOffset - 20))}
            >
              {t("pam.previous")}
            </button>
            <span>{t("pam.count", { count: accountTotal })}</span>
            <button
              type="button"
              disabled={accountOffset + 20 >= accountTotal || busy}
              onClick={() => setAccountOffset(accountOffset + 20)}
            >
              {t("pam.next")}
            </button>
          </div>
          {discovery && (
            <>
              <h2>{t("pam.collected")}</h2>
              <label>
                {t("pam.search")}
                <input
                  type="search"
                  value={query}
                  onChange={(e) => {
                    setQuery(e.target.value);
                    setOffset(0);
                  }}
                />
              </label>
              <div className="pam-table">
                <table>
                  <thead>
                    <tr>
                      {["account", "identity", "enabled", "action"].map((k) => (
                        <th key={k} scope="col">
                          {t("pam." + k)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.slice(offset, offset + 20).map((p) => (
                      <tr key={p.principal_id}>
                        <td>
                          {p.username}
                          {p.host ? "@" + p.host : ""}
                          <small>{p.auth_plugin}</small>
                        </td>
                        <td>{p.principal_id}</td>
                        <td>{t(p.enabled ? "pam.yes" : "pam.no")}</td>
                        <td>
                          {enroll && (
                            <button
                              type="button"
                              disabled={busy || !p.enabled}
                              onClick={() => void choose(p)}
                            >
                              {t("pam.enroll")}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="pam-pages">
                <button
                  type="button"
                  disabled={!offset}
                  onClick={() => setOffset(Math.max(0, offset - 20))}
                >
                  {t("pam.previous")}
                </button>
                <span>{t("pam.count", { count: filtered.length })}</span>
                <button
                  type="button"
                  disabled={offset + 20 >= filtered.length}
                  onClick={() => setOffset(offset + 20)}
                >
                  {t("pam.next")}
                </button>
              </div>
            </>
          )}
          {principal && enroll && (
            <form className="pam-enroll" onSubmit={(e) => void makePreview(e)}>
              <h2>
                {t(existing ? "pam.pinExisting" : "pam.enrollNew")}: {principal.username}
                {principal.host ? "@" + principal.host : ""}
              </h2>
              <p>{t("pam.enrollHelp")}</p>
              <code>{principal.principal_id}</code>
              <fieldset disabled={busy || !!preview}>
                <label>
                  {t("pam.name")}
                  <input
                    required
                    maxLength={120}
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </label>
                <label>
                  {t(
                    existing?.credential_type === "password"
                      ? "pam.passwordExisting"
                      : "pam.passwordNew",
                  )}
                  <input
                    type="password"
                    autoComplete="new-password"
                    value={password}
                    required={!existing || existing.credential_type !== "password"}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={automatic}
                    onChange={(e) => setAutomatic(e.target.checked)}
                  />
                  {t("pam.automatic")}
                </label>
              </fieldset>
              {!preview ? (
                <button type="submit" disabled={busy}>
                  {t("pam.preview")}
                </button>
              ) : (
                <div className="pam-actions">
                  <p>{t("pam.previewReady")}</p>
                  <button type="button" disabled={busy} onClick={() => void commit()}>
                    {t("pam.commit")}
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      setPreview(null);
                      pending.current = null;
                    }}
                  >
                    {t("pam.edit")}
                  </button>
                </div>
              )}
            </form>
          )}
          <p className="pam-footnote">{t("pam.boundary")}</p>
        </>
      )}
    </section>
  );
}
