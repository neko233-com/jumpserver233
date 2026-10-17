import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { usePermissions } from "../auth/usePermissions";
import { toggleLang } from "../i18n";
import type { ManagedAccount } from "./managedAccounts";
import "./managed-accounts.css";
const RemoteAccountsPanel = lazy(() => import("./RemoteAccountsPanel"));

type AccountPage = { results: ManagedAccount[]; total: number; version: string };
type Activity = {
  at: string;
  action: string;
  actor: { name: string };
  username: string;
};
type Draft = {
  username: string;
  name: string;
  remark: string;
  active: boolean;
  credential_type: "password" | "ssh_key";
  password: string;
  private_key: string;
  private_key_passphrase: string;
  password_rotation_enabled: boolean;
  key_rotation_enabled: boolean;
};
const emptyDraft = (): Draft => ({
  username: "",
  name: "",
  remark: "",
  active: true,
  credential_type: "password",
  password: "",
  private_key: "",
  private_key_passphrase: "",
  password_rotation_enabled: true,
  key_rotation_enabled: false,
});

class AccountRequestError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}
async function checkResponse(response: Response) {
  if (response.ok) return response;
  let code = "";
  try {
    code = (await response.json()).detail;
  } catch {
    /* No response body. */
  }
  const known: Record<string, string> = {
    credential_changed_during_verification: "conflict",
    account_username_exists: "duplicate",
    account_activity_full: "full",
    password_rotation_in_progress: "pending",
    ssh_key_change_conflict: "pending",
    shared_credential_conflict: "sharedConflict",
  };
  throw new AccountRequestError(known[code] || (response.status === 404 ? "notFound" : "failed"));
}

export default function ManagedAccountsDialog({
  assetId,
  assetName,
  selectedId,
  accessToken,
  discovered,
  onSelect,
  onChanged,
  onClose,
}: {
  assetId: string;
  assetName: string;
  selectedId: string;
  accessToken: string;
  discovered?: { id: string; username: string };
  onSelect: (account: ManagedAccount) => Promise<void>;
  onChanged: () => void;
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const { allows } = usePermissions();
  const canManage = allows("accounts.manage"),
    canRotate = allows("assets.rotate");
  const [page, setPage] = useState<AccountPage>({ results: [], total: 0, version: "" });
  const [offset, setOffset] = useState(0),
    [queryInput, setQueryInput] = useState(discovered?.username || ""),
    [query, setQuery] = useState(discovered?.username || "");
  const [reload, setReload] = useState(0),
    [loadedKey, setLoadedKey] = useState(""),
    [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [remoteOpen, setRemoteOpen] = useState(false);
  const [formOpen, setFormOpen] = useState(false),
    [editing, setEditing] = useState<ManagedAccount | null>(null);
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  const [removing, setRemoving] = useState<ManagedAccount | null>(null);
  const [activity, setActivity] = useState<ManagedAccount | null>(null),
    [activityOffset, setActivityOffset] = useState(0);
  const [events, setEvents] = useState<{ results: Activity[]; total: number }>({
    results: [],
    total: 0,
  });
  const base = `/api/v1/assets/${encodeURIComponent(assetId)}/accounts`;
  const requestKey = JSON.stringify([base, offset, query, reload]);
  const loading = loadedKey !== requestKey;
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(path, {
        ...init,
        headers,
        signal: init?.signal || AbortSignal.timeout(15_000),
      }).then(checkResponse);
    },
    [accessToken],
  );
  const fail = useCallback(
    (e: unknown) => setError(e instanceof AccountRequestError ? e.code : "failed"),
    [],
  );

  useEffect(() => {
    const c = new AbortController();
    void request(`${base}?offset=${offset}&limit=20&q=${encodeURIComponent(query)}`, {
      signal: c.signal,
    })
      .then((r) => r.json())
      .then((data: AccountPage) => {
        if (
          !Array.isArray(data.results) ||
          !Number.isSafeInteger(data.total) ||
          typeof data.version !== "string"
        )
          throw Error();
        if (!c.signal.aborted) {
          setPage(data);
          setLoadedKey(requestKey);
        }
      })
      .catch((e) => {
        if (!c.signal.aborted) {
          fail(e);
          setPage({ results: [], total: 0, version: "" });
          setLoadedKey(requestKey);
        }
      });
    return () => c.abort();
  }, [base, offset, query, reload, request, requestKey, fail]);
  useEffect(() => {
    if (!activity) return;
    const c = new AbortController();
    void request(
      `${base}/${encodeURIComponent(activity.id)}/activity?offset=${activityOffset}&limit=20`,
      { signal: c.signal },
    )
      .then((r) => r.json())
      .then((data: { results: Activity[]; total: number }) => {
        if (!Array.isArray(data.results) || !Number.isSafeInteger(data.total)) throw Error();
        if (!c.signal.aborted) setEvents(data);
      })
      .catch((e) => {
        if (!c.signal.aborted) fail(e);
      });
    return () => c.abort();
  }, [activity, activityOffset, base, reload, request, fail]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [onClose]);

  function beginEdit(a: ManagedAccount | null) {
    setEditing(a);
    setDraft(
      a
        ? {
            ...emptyDraft(),
            username: a.username,
            name: a.name,
            remark: a.remark,
            active: a.active,
            credential_type: a.credential_type,
            password_rotation_enabled: a.password_rotation_enabled,
            key_rotation_enabled: a.key_rotation_enabled,
          }
        : { ...emptyDraft(), username: discovered?.username || "" },
    );
    setFormOpen(true);
    setRemoving(null);
    setError("");
  }
  function closeForm() {
    setDraft(emptyDraft());
    setEditing(null);
    setFormOpen(false);
  }
  async function save(e: React.SubmitEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = {
        username: draft.username,
        name: draft.name,
        remark: draft.remark,
        active: draft.active,
        credential_type: draft.credential_type,
        password: draft.credential_type === "password" ? draft.password : "",
        private_key: draft.credential_type === "ssh_key" ? draft.private_key : "",
        private_key_passphrase:
          draft.credential_type === "ssh_key" ? draft.private_key_passphrase : "",
        version: editing?.version || page.version,
        ...(discovered && draft.username === discovered.username
          ? { discovery_id: discovered.id }
          : {}),
        ...(canRotate
          ? {
              password_rotation_enabled: draft.password_rotation_enabled,
              key_rotation_enabled:
                draft.credential_type === "ssh_key" && draft.key_rotation_enabled,
            }
          : {}),
      };
      await request(editing ? `${base}/${encodeURIComponent(editing.id)}` : base, {
        method: editing ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      closeForm();
      setReload((v) => v + 1);
      onChanged();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }
  async function remove() {
    if (!removing) return;
    setBusy(true);
    setError("");
    try {
      await request(`${base}/${encodeURIComponent(removing.id)}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ version: removing.version }),
      });
      setRemoving(null);
      setActivity(null);
      setOffset(0);
      setReload((v) => v + 1);
      onChanged();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="asset-modal-backdrop">
      <section
        className="asset-modal managed-accounts-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="managed-accounts-title"
      >
        <header>
          <h2 id="managed-accounts-title">{t("managedAccounts.title", { name: assetName })}</h2>
          <div className="managed-accounts-actions">
            <button type="button" className="button-secondary" onClick={() => void toggleLang()}>
              {t("sharing.language")}
            </button>
            <button type="button" className="button-secondary" onClick={onClose}>
              {t("audit.closeCommands")}
            </button>
          </div>
        </header>
        <p className="settings-help">{t("managedAccounts.hint")}</p>
        <button
          type="button"
          className="button-secondary"
          aria-expanded={remoteOpen}
          onClick={() => setRemoteOpen((v) => !v)}
        >
          {t("remoteAccounts.title")}
        </button>
        {remoteOpen && (
          <Suspense fallback={<p role="status">{t("managedAccounts.loading")}</p>}>
            <RemoteAccountsPanel
              assetId={assetId}
              collectorId={selectedId}
              accessToken={accessToken}
              onChanged={() => {
                setReload((v) => v + 1);
                onChanged();
              }}
            />
          </Suspense>
        )}
        {discovered && (
          <p className="settings-help">
            {t("managedAccounts.discoveryHint", { username: discovered.username })}
          </p>
        )}
        <form
          className="managed-accounts-actions"
          onSubmit={(e) => {
            e.preventDefault();
            setOffset(0);
            setQuery(queryInput);
            setError("");
          }}
        >
          <input
            aria-label={t("managedAccounts.search")}
            maxLength={128}
            value={queryInput}
            onChange={(e) => setQueryInput(e.target.value)}
            placeholder={t("managedAccounts.search")}
          />
          <button type="submit" className="button-secondary">
            {t("managedAccounts.search")}
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={() => {
              setError("");
              setReload((v) => v + 1);
            }}
          >
            {t("audit.refresh")}
          </button>
          {canManage && (
            <button
              type="button"
              className="button-primary"
              disabled={busy || !page.version}
              onClick={() => beginEdit(null)}
            >
              {t("managedAccounts.add")}
            </button>
          )}
        </form>
        {error && (
          <p className="asset-error" role="alert">
            {t(`managedAccounts.errors.${error}`)}
          </p>
        )}
        {loading && <p role="status">{t("managedAccounts.loading")}</p>}
        <div className="managed-accounts-table">
          <table>
            <thead>
              <tr>
                <th>{t("managedAccounts.username")}</th>
                <th>{t("managedAccounts.credentialType")}</th>
                <th>{t("managedAccounts.status")}</th>
                <th>{t("assets.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {page.results.map((a) => (
                <tr key={a.id}>
                  <td>
                    <strong>{a.username}</strong>
                    {a.default && <small>{t("managedAccounts.primary")}</small>}
                    <small>{a.name}</small>
                    {a.discovery_id && (
                      <small>
                        {t(
                          discovered?.id === a.discovery_id
                            ? "managedAccounts.discoveryMatched"
                            : "managedAccounts.discoveryLinked",
                        )}
                      </small>
                    )}
                    {a.key_fingerprint && <code>{a.key_fingerprint}</code>}
                  </td>
                  <td>
                    {t(
                      a.credential_type === "ssh_key"
                        ? "managedAccounts.key"
                        : "managedAccounts.password",
                    )}
                  </td>
                  <td>
                    {t(a.active ? "managedAccounts.enabled" : "managedAccounts.disabled")}
                    {a.remote_account && (
                      <small>{t(`remoteAccounts.accountStates.${a.remote_account.state}`)}</small>
                    )}
                    <small>
                      {t(
                        a.credential_type === "ssh_key"
                          ? a.key_rotation_enabled
                            ? "managedAccounts.keyRotationOn"
                            : "managedAccounts.rotationOff"
                          : a.password_rotation_enabled
                            ? "managedAccounts.rotationOn"
                            : "managedAccounts.rotationOff",
                      )}
                    </small>
                  </td>
                  <td>
                    <div className="managed-accounts-actions">
                      <button
                        type="button"
                        className="button-text"
                        disabled={busy || !a.active || a.id === selectedId}
                        onClick={() => {
                          setBusy(true);
                          void onSelect(a)
                            .then(onClose)
                            .catch(fail)
                            .finally(() => setBusy(false));
                        }}
                      >
                        {t(
                          a.id === selectedId ? "managedAccounts.selected" : "managedAccounts.use",
                        )}
                      </button>
                      {canManage && (
                        <button
                          type="button"
                          className="button-text"
                          disabled={busy}
                          onClick={() => beginEdit(a)}
                        >
                          {t("assets.edit")}
                        </button>
                      )}
                      {(canManage || allows("accounts.view")) && (
                        <button
                          type="button"
                          className="button-text"
                          onClick={() => {
                            setActivity(a);
                            setActivityOffset(0);
                            setEvents({ results: [], total: 0 });
                          }}
                        >
                          {t("managedAccounts.activity")}
                        </button>
                      )}
                      {canManage && !a.default && (
                        <button
                          type="button"
                          className="button-text"
                          disabled={busy}
                          onClick={() => {
                            closeForm();
                            setRemoving(a);
                          }}
                        >
                          {t("managedAccounts.remove")}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!loading && page.total === 0 && <p>{t("managedAccounts.empty")}</p>}
        <div className="managed-accounts-actions">
          <button
            type="button"
            className="button-secondary"
            disabled={loading || offset === 0}
            onClick={() => setOffset(Math.max(0, offset - 20))}
          >
            {t("managedAccounts.previous")}
          </button>
          <span>
            {t("managedAccounts.showing", {
              from: page.total ? offset + 1 : 0,
              to: Math.min(offset + page.results.length, page.total),
              total: page.total,
            })}
          </span>
          <button
            type="button"
            className="button-secondary"
            disabled={loading || offset + page.results.length >= page.total}
            onClick={() => setOffset(offset + 20)}
          >
            {t("managedAccounts.next")}
          </button>
        </div>
        {removing && (
          <section className="managed-accounts-confirm" aria-label={t("managedAccounts.remove")}>
            <p>{t("managedAccounts.removeConfirm", { username: removing.username })}</p>
            <div className="managed-accounts-actions">
              <button
                type="button"
                className="button-secondary"
                disabled={busy}
                onClick={() => setRemoving(null)}
              >
                {t("assets.cancel")}
              </button>
              <button
                type="button"
                className="button-primary"
                disabled={busy}
                onClick={() => void remove()}
              >
                {t("managedAccounts.remove")}
              </button>
            </div>
          </section>
        )}
        {formOpen && canManage && (
          <form className="managed-accounts-form" onSubmit={(e) => void save(e)}>
            <h3>{t(editing ? "managedAccounts.edit" : "managedAccounts.add")}</h3>
            <div className="managed-accounts-fields">
              <label>
                <span>{t("managedAccounts.username")}</span>
                <input
                  aria-label={t("managedAccounts.username")}
                  required
                  maxLength={128}
                  disabled={Boolean(editing)}
                  autoComplete="off"
                  value={draft.username}
                  onChange={(e) => setDraft({ ...draft, username: e.target.value })}
                />
              </label>
              <label>
                <span>{t("managedAccounts.name")}</span>
                <input
                  aria-label={t("managedAccounts.name")}
                  maxLength={120}
                  value={draft.name}
                  onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                />
              </label>
              <label>
                <span>{t("managedAccounts.credentialType")}</span>
                <select
                  aria-label={t("managedAccounts.credentialType")}
                  value={draft.credential_type}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      credential_type: e.target.value as Draft["credential_type"],
                      password: "",
                      private_key: "",
                      private_key_passphrase: "",
                    })
                  }
                >
                  <option value="password">{t("managedAccounts.password")}</option>
                  <option value="ssh_key">{t("managedAccounts.key")}</option>
                </select>
              </label>
              {draft.credential_type === "password" ? (
                <label>
                  <span>{t("managedAccounts.newPassword")}</span>
                  <input
                    aria-label={t("managedAccounts.newPassword")}
                    type="password"
                    required={!editing || editing.credential_type !== "password"}
                    maxLength={4096}
                    autoComplete="new-password"
                    value={draft.password}
                    onChange={(e) => setDraft({ ...draft, password: e.target.value })}
                  />
                </label>
              ) : (
                <>
                  <label className="managed-accounts-wide">
                    <span>{t("managedAccounts.key")}</span>
                    <textarea
                      aria-label={t("managedAccounts.key")}
                      required={!editing || editing.credential_type !== "ssh_key"}
                      rows={4}
                      autoComplete="off"
                      spellCheck={false}
                      value={draft.private_key}
                      onChange={(e) => setDraft({ ...draft, private_key: e.target.value })}
                    />
                  </label>
                  <label>
                    <span>{t("managedAccounts.passphrase")}</span>
                    <input
                      aria-label={t("managedAccounts.passphrase")}
                      type="password"
                      autoComplete="new-password"
                      maxLength={4096}
                      value={draft.private_key_passphrase}
                      onChange={(e) =>
                        setDraft({ ...draft, private_key_passphrase: e.target.value })
                      }
                    />
                  </label>
                </>
              )}
              <label className="managed-accounts-wide">
                <span>{t("managedAccounts.note")}</span>
                <input
                  aria-label={t("managedAccounts.note")}
                  maxLength={512}
                  value={draft.remark}
                  onChange={(e) => setDraft({ ...draft, remark: e.target.value })}
                />
              </label>
            </div>
            <p className="settings-help">
              {t(editing ? "managedAccounts.secretHelp" : "managedAccounts.secretNew")}
            </p>
            <div className="managed-accounts-options">
              <label>
                <input
                  type="checkbox"
                  checked={draft.active}
                  onChange={(e) => setDraft({ ...draft, active: e.target.checked })}
                />
                <span>{t("managedAccounts.active")}</span>
              </label>
              {canRotate &&
                (draft.credential_type === "password" ? (
                  <label>
                    <input
                      type="checkbox"
                      checked={draft.password_rotation_enabled}
                      onChange={(e) =>
                        setDraft({ ...draft, password_rotation_enabled: e.target.checked })
                      }
                    />
                    <span>{t("managedAccounts.rotationOn")}</span>
                  </label>
                ) : (
                  <label>
                    <input
                      type="checkbox"
                      checked={draft.key_rotation_enabled}
                      onChange={(e) =>
                        setDraft({ ...draft, key_rotation_enabled: e.target.checked })
                      }
                    />
                    <span>{t("managedAccounts.keyRotationOn")}</span>
                  </label>
                ))}
            </div>
            <div className="managed-accounts-actions">
              <button
                type="button"
                className="button-secondary"
                disabled={busy}
                onClick={closeForm}
              >
                {t("assets.cancel")}
              </button>
              <button
                type="submit"
                className="button-primary"
                disabled={busy || loading || !page.version}
              >
                {t("assets.save")}
              </button>
            </div>
          </form>
        )}
        {activity && (
          <section className="managed-accounts-activity" aria-label={t("managedAccounts.activity")}>
            <h3>
              {t("managedAccounts.activity")} · {activity.username}
            </h3>
            <ul>
              {events.results.map((e, i) => (
                <li key={`${e.at}-${i}`}>
                  <time dateTime={e.at}>{new Date(e.at).toLocaleString(i18n.language)}</time> ·{" "}
                  {e.actor.name} · {e.username} ·{" "}
                  {t(
                    `managedAccounts.events.${["created", "updated", "deleted"].includes(e.action) ? e.action : "updated"}`,
                  )}
                </li>
              ))}
            </ul>
            <div className="managed-accounts-actions">
              <button
                type="button"
                className="button-secondary"
                disabled={activityOffset === 0}
                onClick={() => setActivityOffset(Math.max(0, activityOffset - 20))}
              >
                {t("managedAccounts.previous")}
              </button>
              <span>{events.total}</span>
              <button
                type="button"
                className="button-secondary"
                disabled={activityOffset + events.results.length >= events.total}
                onClick={() => setActivityOffset(activityOffset + 20)}
              >
                {t("managedAccounts.next")}
              </button>
              <button type="button" className="button-secondary" onClick={() => setActivity(null)}>
                {t("audit.closeCommands")}
              </button>
            </div>
          </section>
        )}
      </section>
    </div>
  );
}
