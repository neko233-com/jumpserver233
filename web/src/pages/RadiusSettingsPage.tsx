import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/radius/register";
type Endpoint = {
  host: string;
  port: number;
  transport: string;
  allow_udp: boolean;
  server_name: string;
  ca_pem: string;
  client_certificate: string;
  nas_identifier: string;
  timeout_seconds: number;
  attempts: number;
};
type Secrets = {
  shared_secret?: string;
  client_key?: string;
  clear_shared_secret?: boolean;
  clear_client_key?: boolean;
};
type Config = {
  enabled: boolean;
  provision_new: boolean;
  realm: string;
  primary: Endpoint;
  factor: Endpoint;
  factor_policy: string;
  factor_user_ids: string[];
  bindings: Record<string, string>;
  revision: number;
};
type Snapshot = Config & {
  has_primary_secret: boolean;
  has_primary_key: boolean;
  has_factor_secret: boolean;
  has_factor_key: boolean;
};
type Event = {
  id: string;
  at: string;
  actor: string;
  revision: number;
  action: string;
  digest: string;
};
const endpoint: Endpoint = {
  host: "",
  port: 2083,
  transport: "tls",
  allow_udp: false,
  server_name: "",
  ca_pem: "",
  client_certificate: "",
  nas_identifier: "jumpserver233",
  timeout_seconds: 3,
  attempts: 2,
};
const empty: Config = {
  enabled: false,
  provision_new: false,
  realm: "default",
  primary: endpoint,
  factor: endpoint,
  factor_policy: "disabled",
  factor_user_ids: [],
  bindings: {},
  revision: 0,
};
function endpointValue(v: Endpoint): Endpoint {
  return {
    ...endpoint,
    ...v,
    port: v.port || endpoint.port,
    transport: v.transport || endpoint.transport,
    timeout_seconds: v.timeout_seconds || endpoint.timeout_seconds,
    attempts: v.attempts || endpoint.attempts,
    nas_identifier: v.nas_identifier || endpoint.nas_identifier,
  };
}
function configOnly(v: Snapshot): Config {
  return {
    enabled: v.enabled,
    provision_new: v.provision_new,
    realm: v.realm,
    primary: endpointValue(v.primary),
    factor: endpointValue(v.factor),
    factor_policy: v.factor_policy,
    factor_user_ids: v.factor_user_ids || [],
    bindings: v.bindings || {},
    revision: v.revision,
  };
}
export default function RadiusSettingsPage() {
  const { t, i18n } = useTranslation(),
    { accessToken } = useAuth(),
    { allows, ready } = usePermissions(),
    canManage = allows("security.manage");
  const [config, setConfig] = useState<Config>(empty),
    [stored, setStored] = useState<Snapshot | null>(null),
    [primarySecrets, setPrimarySecrets] = useState<Secrets>({}),
    [factorSecrets, setFactorSecrets] = useState<Secrets>({}),
    [users, setUsers] = useState<{ id: string; username: string }[]>([]),
    [events, setEvents] = useState<Event[]>([]),
    [offset, setOffset] = useState(0),
    [total, setTotal] = useState(0),
    [busy, setBusy] = useState(false),
    [loaded, setLoaded] = useState(false),
    [error, setError] = useState(""),
    [saved, setSaved] = useState(false),
    [mapping, setMapping] = useState(""),
    [remote, setRemote] = useState(""),
    [probe, setProbe] = useState("primary"),
    [probeName, setProbeName] = useState(""),
    [probePassword, setProbePassword] = useState(""),
    [probeCode, setProbeCode] = useState<number | null>(null);
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", "Bearer " + accessToken);
      if (init?.body) headers.set("Content-Type", "application/json");
      return fetch("/api/v1/settings/security/radius" + path, { ...init, headers });
    },
    [accessToken],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const [a, b, u] = await Promise.all([
          request("", { signal }),
          request(`/audit?offset=${offset}&limit=25`, { signal }),
          fetch("/api/v1/settings/security/radius/users", {
            headers: accessToken ? { Authorization: "Bearer " + accessToken } : {},
            signal,
          }),
        ]);
        if (!a.ok || !b.ok || !u.ok) throw Error();
        const [v, e, list] = await Promise.all([
          a.json() as Promise<Snapshot>,
          b.json() as Promise<{ results: Event[]; total: number }>,
          u.json() as Promise<{ id: string; username: string }[]>,
        ]);
        if (signal?.aborted) return;
        setStored(v);
        setConfig(configOnly(v));
        setEvents(e.results);
        setTotal(e.total);
        setUsers(list);
        setPrimarySecrets({});
        setFactorSecrets({});
        setLoaded(true);
        setError("");
      } catch {
        if (!signal?.aborted) setError("error");
      }
    },
    [request, offset, accessToken],
  );
  useEffect(() => {
    if (!canManage) return;
    const ctl = new AbortController();
    queueMicrotask(() => {
      if (!ctl.signal.aborted) void load(ctl.signal);
    });
    return () => ctl.abort();
  }, [canManage, load]);
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    setSaved(false);
    try {
      const r = await request("", {
        method: "PUT",
        body: JSON.stringify({
          ...config,
          primary_secrets: primarySecrets,
          factor_secrets: factorSecrets,
        }),
      });
      if (!r.ok) {
        setError(r.status === 409 ? "conflict" : "error");
        return;
      }
      setPrimarySecrets({});
      setFactorSecrets({});
      await load();
      setSaved(true);
    } catch {
      setError("error");
    } finally {
      setBusy(false);
    }
  };
  const check = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    setProbeCode(null);
    try {
      const r = await request("/check", {
        method: "POST",
        body: JSON.stringify({ endpoint: probe, username: probeName, password: probePassword }),
      });
      if (!r.ok) throw Error();
      const v = (await r.json()) as { result: number };
      setProbeCode(v.result);
    } catch {
      setError("error");
    } finally {
      setProbePassword("");
      setBusy(false);
    }
  };
  const update = (key: "primary" | "factor", value: Endpoint) =>
    setConfig((v) => ({ ...v, [key]: value }));
  if (!ready) return null;
  if (!canManage) return <p role="alert">{t("radius.denied")}</p>;
  return (
    <section className="jobs-page radius-settings">
      <h1>{t("radius.title")}</h1>
      <p>{t("radius.description")}</p>
      {error && <p role="alert">{t("radius." + error)}</p>}
      {saved && <p role="status">{t("radius.saved")}</p>}
      <p>
        {t("radius.revision")}: {config.revision}
      </p>
      <form className="radius-form" onSubmit={(e) => void save(e)}>
        <fieldset disabled={!loaded || busy}>
          <label>
            <input
              type="checkbox"
              checked={config.enabled}
              onChange={(e) => setConfig((v) => ({ ...v, enabled: e.target.checked }))}
            />
            {t("radius.enabled")}
          </label>
          <label>
            <input
              type="checkbox"
              checked={config.provision_new}
              onChange={(e) => setConfig((v) => ({ ...v, provision_new: e.target.checked }))}
            />
            {t("radius.provision")}
          </label>
          <label>
            {t("radius.realm")}
            <input
              required
              maxLength={64}
              value={config.realm}
              onChange={(e) => setConfig((v) => ({ ...v, realm: e.target.value }))}
            />
          </label>
          <EndpointEditor
            title="primary"
            value={config.primary}
            onChange={(v) => update("primary", v)}
            secret={primarySecrets}
            setSecret={setPrimarySecrets}
            hasSecret={Boolean(stored?.has_primary_secret)}
            hasKey={Boolean(stored?.has_primary_key)}
          />
          <label>
            {t("radius.factorPolicy")}
            <select
              value={config.factor_policy}
              onChange={(e) =>
                setConfig((v) => ({ ...v, factor_policy: e.target.value, factor_user_ids: [] }))
              }
            >
              {["disabled", "all", "admins", "users"].map((p) => (
                <option key={p} value={p}>
                  {t("radius." + p)}
                </option>
              ))}
            </select>
          </label>
          <p>{t("radius.policyHint")}</p>
          {config.factor_policy === "users" && (
            <fieldset>
              <legend>{t("radius.targets")}</legend>
              {users.map((u) => (
                <label key={u.id}>
                  <input
                    type="checkbox"
                    checked={config.factor_user_ids.includes(u.id)}
                    onChange={(e) =>
                      setConfig((v) => ({
                        ...v,
                        factor_user_ids: e.target.checked
                          ? [...v.factor_user_ids, u.id]
                          : v.factor_user_ids.filter((id) => id !== u.id),
                      }))
                    }
                  />
                  {u.username}
                </label>
              ))}
            </fieldset>
          )}
          <EndpointEditor
            title="factor"
            value={config.factor}
            onChange={(v) => update("factor", v)}
            secret={factorSecrets}
            setSecret={setFactorSecrets}
            hasSecret={Boolean(stored?.has_factor_secret)}
            hasKey={Boolean(stored?.has_factor_key)}
          />
          <details>
            <summary>{t("radius.bindings")}</summary>
            <p>{t("radius.mappingHint")}</p>
            <label>
              {t("radius.user")}
              <select value={mapping} onChange={(e) => setMapping(e.target.value)}>
                <option value="">—</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.username}
                  </option>
                ))}
              </select>
            </label>
            <label>
              {t("radius.remoteName")}
              <input maxLength={128} value={remote} onChange={(e) => setRemote(e.target.value)} />
            </label>
            <button
              type="button"
              disabled={!mapping || !remote.trim()}
              onClick={() => {
                setConfig((v) => ({ ...v, bindings: { ...v.bindings, [mapping]: remote.trim() } }));
                setRemote("");
              }}
            >
              {t("radius.add")}
            </button>
            <ul>
              {Object.entries(config.bindings).map(([id, name]) => (
                <li key={id}>
                  {users.find((u) => u.id === id)?.username || id} · {name}{" "}
                  <button
                    type="button"
                    onClick={() =>
                      setConfig((v) => {
                        const bindings = { ...v.bindings };
                        delete bindings[id];
                        return { ...v, bindings };
                      })
                    }
                  >
                    {t("radius.remove")}
                  </button>
                </li>
              ))}
            </ul>
          </details>
          <button disabled={busy || !loaded}>{t("radius.save")}</button>
          <button type="button" disabled={busy} onClick={() => void load()}>
            {t("radius.reload")}
          </button>
        </fieldset>
      </form>
      <details>
        <summary>{t("radius.check")}</summary>
        <p>{t("radius.probeHint")}</p>
        <form className="radius-form" onSubmit={(e) => void check(e)}>
          <label>
            {t("radius.transport")}
            <select value={probe} onChange={(e) => setProbe(e.target.value)}>
              <option value="primary">{t("radius.primary")}</option>
              <option value="factor">{t("radius.factor")}</option>
            </select>
          </label>
          <label>
            {t("radius.remoteName")}
            <input
              required
              maxLength={128}
              value={probeName}
              onChange={(e) => setProbeName(e.target.value)}
            />
          </label>
          <label>
            {t("radius.probePassword")}
            <input
              type="password"
              maxLength={128}
              autoComplete="off"
              value={probePassword}
              onChange={(e) => setProbePassword(e.target.value)}
            />
          </label>
          <button disabled={busy || !loaded}>{t("radius.check")}</button>
        </form>
        {probeCode !== null && <p role="status">{t("radius.probeResult", { code: probeCode })}</p>}
      </details>
      <h2>{t("radius.audit")}</h2>
      <div className="jobs-table-scroll">
        <table className="jobs-table">
          <thead>
            <tr>
              {["at", "actor", "revision", "action", "digest"].map((k) => (
                <th key={k}>{t("radius." + k)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.map((v) => (
              <tr key={v.id}>
                <td>{new Date(v.at).toLocaleString(i18n.language)}</td>
                <td>{v.actor}</td>
                <td>{v.revision}</td>
                <td>{t("radius." + v.action)}</td>
                <td>
                  <code>{v.digest}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <nav aria-label={t("radius.audit")}>
        <button disabled={!offset} onClick={() => setOffset((v) => Math.max(0, v - 25))}>
          {t("jobs.previous")}
        </button>{" "}
        {total ? offset + 1 : 0}–{Math.min(offset + 25, total)} / {total}{" "}
        <button disabled={offset + 25 >= total} onClick={() => setOffset((v) => v + 25)}>
          {t("jobs.next")}
        </button>
      </nav>
    </section>
  );
}
function EndpointEditor({
  title,
  value,
  onChange,
  secret,
  setSecret,
  hasSecret,
  hasKey,
}: {
  title: string;
  value: Endpoint;
  onChange: (v: Endpoint) => void;
  secret: Secrets;
  setSecret: (s: Secrets) => void;
  hasSecret: boolean;
  hasKey: boolean;
}) {
  const { t } = useTranslation();
  return (
    <details>
      <summary>{t("radius." + title)}</summary>
      <label>
        {t("radius.host")}
        <input
          aria-label={t("radius." + title) + " · " + t("radius.host")}
          maxLength={253}
          value={value.host}
          onChange={(e) => onChange({ ...value, host: e.target.value })}
        />
      </label>
      <label>
        {t("radius.port")}
        <input
          type="number"
          min={1}
          max={65535}
          value={value.port}
          onChange={(e) => onChange({ ...value, port: Number(e.target.value) })}
        />
      </label>
      <label>
        {t("radius.transport")}
        <select
          value={value.transport}
          onChange={(e) =>
            onChange({
              ...value,
              transport: e.target.value,
              port: e.target.value === "udp" ? 1812 : 2083,
              ...(e.target.value === "udp"
                ? { server_name: "", ca_pem: "", client_certificate: "" }
                : { allow_udp: false }),
            })
          }
        >
          <option value="tls">{t("radius.tls")}</option>
          <option value="udp">{t("radius.udp")}</option>
        </select>
      </label>
      {value.transport === "udp" ? (
        <>
          <label>
            <input
              type="checkbox"
              checked={value.allow_udp}
              onChange={(e) => onChange({ ...value, allow_udp: e.target.checked })}
            />
            {t("radius.allowUDP")}
          </label>
          <p>{t("radius.udpHint")}</p>
          <label>
            {t("radius.secret")}
            <input
              type="password"
              autoComplete="new-password"
              maxLength={256}
              value={secret.shared_secret || ""}
              placeholder={hasSecret ? t("radius.stored") : ""}
              onChange={(e) => setSecret({ ...secret, shared_secret: e.target.value })}
            />
          </label>
          <label>
            <input
              type="checkbox"
              checked={Boolean(secret.clear_shared_secret)}
              onChange={(e) => setSecret({ ...secret, clear_shared_secret: e.target.checked })}
            />
            {t("radius.clearSecret")}
          </label>
        </>
      ) : (
        <>
          {(["server_name", "ca_pem", "client_certificate"] as const).map((key) => (
            <label key={key}>
              {t(
                "radius." +
                  { server_name: "serverName", ca_pem: "ca", client_certificate: "certificate" }[
                    key
                  ],
              )}
              {key === "server_name" ? (
                <input
                  value={value[key]}
                  onChange={(e) => onChange({ ...value, [key]: e.target.value })}
                />
              ) : (
                <textarea
                  rows={4}
                  spellCheck={false}
                  autoCapitalize="off"
                  value={value[key]}
                  onChange={(e) => onChange({ ...value, [key]: e.target.value })}
                />
              )}
            </label>
          ))}
          <label>
            {t("radius.key")}
            <textarea
              rows={4}
              spellCheck={false}
              autoCapitalize="off"
              autoComplete="off"
              value={secret.client_key || ""}
              placeholder={hasKey ? t("radius.stored") : ""}
              onChange={(e) => setSecret({ ...secret, client_key: e.target.value })}
            />
          </label>
          <label>
            <input
              type="checkbox"
              checked={Boolean(secret.clear_client_key)}
              onChange={(e) => setSecret({ ...secret, clear_client_key: e.target.checked })}
            />
            {t("radius.clearKey")}
          </label>
        </>
      )}
      {(["nas_identifier", "timeout_seconds", "attempts"] as const).map((k) => (
        <label key={k}>
          {t(
            "radius." +
              { nas_identifier: "nas", timeout_seconds: "timeout", attempts: "attempts" }[k],
          )}
          <input
            type={k === "nas_identifier" ? "text" : "number"}
            min={1}
            max={k === "attempts" ? 3 : 5}
            value={value[k]}
            onChange={(e) =>
              onChange({
                ...value,
                [k]: k === "nas_identifier" ? e.target.value : Number(e.target.value),
              })
            }
          />
        </label>
      ))}
    </details>
  );
}
