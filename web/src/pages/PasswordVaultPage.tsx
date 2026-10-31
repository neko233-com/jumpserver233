import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import "./LabelsPage.css";
import "./PasswordVaultPage.css";

type Item = {
  id: string;
  kind: "website" | "game" | "service";
  title: string;
  site: string;
  username: string;
  shared: boolean;
  can_manage_sharing?: boolean;
  revision: number;
};
type Draft = Item & { password: string };
type Grant = { id: string; item_id: string; expires: string };
type Event = { at: string; action: string; item_id: string; owner: string };
type Issued = { grant_id: string; token: string };
const nonce = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
const fresh = (): Draft => ({
  id: "",
  kind: "website",
  title: "",
  site: "",
  username: "",
  shared: true,
  password: "",
  revision: 0,
});

export default function PasswordVaultPage() {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const [items, setItems] = useState<Item[]>([]);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [issued, setIssued] = useState<Issued | null>(null);
  const [revealed, setRevealed] = useState<{ id: string; password: string } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const pendingCreate = useRef<{ payload: string; requestID: string } | null>(null);
  const pendingGrant = useRef<Record<string, string>>({});
  const request = useCallback(
    async (path: string, method = "GET", body?: unknown) => {
      const response = await fetch(`/api/v1/password-vault/${path}`, {
        method,
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error_code || "vault_unavailable");
      }
      return response.status === 204 ? null : response.json();
    },
    [accessToken],
  );
  const load = useCallback(async () => {
    const [a, b, c] = await Promise.all([request("items"), request("grants"), request("audit")]);
    setItems(a.results);
    setGrants(b.results);
    setEvents(c.results);
  }, [request]);
  useEffect(() => {
    let live = true;
    void Promise.all([request("items"), request("grants"), request("audit")])
      .then(([a, b, c]) => {
        if (live) {
          setItems(a.results);
          setGrants(b.results);
          setEvents(c.results);
        }
      })
      .catch((e: Error) => {
        if (live) setError(e.message);
      });
    return () => {
      live = false;
    };
  }, [request]);
  async function act(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await fn();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "vault_unavailable");
    } finally {
      setBusy(false);
    }
  }
  function save(e: FormEvent) {
    e.preventDefault();
    if (!draft) return;
    void act(async () => {
      const { id, revision, can_manage_sharing: _canManageSharing, ...fields } = draft;
      const payload = JSON.stringify(fields);
      if (!id && pendingCreate.current?.payload !== payload) {
        pendingCreate.current = {
          payload,
          requestID: nonce(),
        };
      }
      await request(
        id ? `items/${encodeURIComponent(id)}` : "items",
        id ? "PUT" : "POST",
        id ? { ...fields, revision } : { ...fields, request_id: pendingCreate.current?.requestID },
      );
      pendingCreate.current = null;
      setDraft(null);
    });
  }
  return (
    <section className="labels-page vault-page">
      <h1>{t("passwordVault.title")}</h1>
      <p>{t("passwordVault.description")}</p>
      {error && (
        <p role="alert">
          {t(
            error === "vault_secure_transport_required"
              ? "passwordVault.secure"
              : error === "vault_conflict"
                ? "passwordVault.conflict"
                : "passwordVault.unavailable",
          )}
        </p>
      )}
      <button
        type="button"
        className="button-primary"
        disabled={busy}
        onClick={() => {
          pendingCreate.current = null;
          setDraft(fresh());
          setRevealed(null);
        }}
      >
        {t("passwordVault.new")}
      </button>
      {draft && (
        <form className="labels-editor" onSubmit={save}>
          <label>
            {t("passwordVault.kind")}
            <select
              value={draft.kind}
              onChange={(e) => setDraft({ ...draft, kind: e.target.value as Draft["kind"] })}
            >
              <option value="website">{t("passwordVault.website")}</option>
              <option value="game">{t("passwordVault.game")}</option>
              <option value="service">{t("passwordVault.service")}</option>
            </select>
          </label>
          <label>
            {t("passwordVault.name")}
            <input
              required
              maxLength={256}
              value={draft.title}
              onChange={(e) => setDraft({ ...draft, title: e.target.value })}
            />
          </label>
          <label>
            {t("passwordVault.site")}
            <input
              maxLength={2048}
              value={draft.site}
              onChange={(e) => setDraft({ ...draft, site: e.target.value })}
            />
          </label>
          <label>
            {t("passwordVault.username")}
            <input
              maxLength={512}
              value={draft.username}
              onChange={(e) => setDraft({ ...draft, username: e.target.value })}
            />
          </label>
          <label>
            {t("passwordVault.password")}
            <input
              type="password"
              required
              autoComplete="new-password"
              value={draft.password}
              onChange={(e) => setDraft({ ...draft, password: e.target.value })}
            />
          </label>
          {(!draft.id || draft.can_manage_sharing) && (
            <label>
              <input
                type="checkbox"
                checked={draft.shared}
                onChange={(e) => setDraft({ ...draft, shared: e.target.checked })}
              />
              {t("passwordVault.shared")}
            </label>
          )}
          <button className="button-primary" disabled={busy}>
            {t("passwordVault.save")}
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={() => {
              pendingCreate.current = null;
              setDraft(null);
            }}
          >
            {t("passwordVault.cancel")}
          </button>
        </form>
      )}
      {items.length === 0 && !error && <p>{t("passwordVault.empty")}</p>}
      <ul className="vault-list">
        {items.map((item) => (
          <li key={item.id}>
            <strong>{item.title}</strong> · {t(`passwordVault.${item.kind}`)} ·{" "}
            {t(item.shared ? "passwordVault.shared" : "passwordVault.private")} · {item.username}{" "}
            {item.site && `· ${item.site}`}
            <div className="vault-actions">
              <button
                type="button"
                disabled={busy}
                onClick={() => setDraft({ ...item, password: "" })}
              >
                {t("passwordVault.edit")}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void act(async () => {
                    const value = await request(`items/${item.id}/reveal`, "POST");
                    setRevealed({ id: item.id, password: value.password });
                  })
                }
              >
                {t("passwordVault.reveal")}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void act(async () => {
                    pendingGrant.current[item.id] ||= nonce();
                    setIssued(
                      await request(`items/${item.id}/grant`, "POST", {
                        request_id: pendingGrant.current[item.id],
                      }),
                    );
                    delete pendingGrant.current[item.id];
                  })
                }
              >
                {t("passwordVault.grant")}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  if (window.confirm(t("passwordVault.confirmDelete")))
                    void act(async () => {
                      await request(`items/${item.id}`, "DELETE", { revision: item.revision });
                      setRevealed(null);
                    });
                }}
              >
                {t("passwordVault.delete")}
              </button>
            </div>
            {revealed?.id === item.id && (
              <p>
                <label>
                  {t("passwordVault.password")}
                  <input readOnly value={revealed.password} />
                </label>
                <button type="button" onClick={() => setRevealed(null)}>
                  {t("passwordVault.close")}
                </button>
              </p>
            )}
          </li>
        ))}
      </ul>
      {issued && (
        <aside className="vault-issued" role="status">
          <p>{t("passwordVault.grantIssued")}</p>
          <label>
            {t("passwordVault.grantID")}
            <input readOnly value={issued.grant_id} />
          </label>
          <label>
            {t("passwordVault.token")}
            <input readOnly value={issued.token} />
          </label>
          <button type="button" onClick={() => setIssued(null)}>
            {t("passwordVault.close")}
          </button>
        </aside>
      )}
      <h2>{t("passwordVault.grants")}</h2>
      <ul className="vault-list vault-secondary">
        {grants.map((grant) => (
          <li key={grant.id}>
            {items.find((item) => item.id === grant.item_id)?.title || grant.item_id} ·{" "}
            {new Date(grant.expires).toLocaleString()}{" "}
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                void act(async () => {
                  await request(`grants/${grant.id}`, "DELETE");
                  setIssued(null);
                })
              }
            >
              {t("passwordVault.revoke")}
            </button>
          </li>
        ))}
      </ul>
      <h2>{t("passwordVault.audit")}</h2>
      <ul className="vault-list vault-secondary">
        {events.map((event, index) => (
          <li key={`${event.at}-${index}`}>
            {new Date(event.at).toLocaleString()} · {event.owner} ·{" "}
            {t(`passwordVault.actions.${event.action}`)} ·{" "}
            {items.find((item) => item.id === event.item_id)?.title || event.item_id}
          </li>
        ))}
      </ul>
    </section>
  );
}
