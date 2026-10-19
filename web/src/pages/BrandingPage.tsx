import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useState,
  type ChangeEvent,
  type CSSProperties,
  type FormEvent,
} from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import { defaults, useBranding, type Branding, type Colors } from "../branding/BrandingContext";
import "../i18n/locales/features/branding/register";
import "./BrandingPage.css";

type Draft = {
  revision: number;
  name_en: string;
  name_zh: string;
  theme: string;
  accent: string;
  login_title_en: string;
  login_title_zh: string;
  footer_en: string;
  footer_zh: string;
  registration_label: string;
  registration_url: string;
  logo?: string;
  icon?: string;
  mark?: string;
  login_image?: string;
};
const slots = {
  logo: "logo_digest",
  icon: "icon_digest",
  mark: "mark_digest",
  login_image: "login_digest",
} as const;
const clearLabels = {
  logo: "clearLogo",
  icon: "clearIcon",
  mark: "clearMark",
  login_image: "clearLoginImage",
} as const;
type ImageKind = keyof typeof slots;
type Audit = {
  at: string;
  actor: string;
  before: Omit<Branding, "colors">;
  after: Omit<Branding, "colors">;
};
type Configuration = { settings: Branding; themes: { id: string; colors: Colors }[] };
const plain = (v: Branding): Draft => ({
  revision: v.revision,
  name_en: v.name_en,
  name_zh: v.name_zh,
  theme: v.theme,
  accent: v.accent,
  login_title_en: v.login_title_en,
  login_title_zh: v.login_title_zh,
  footer_en: v.footer_en,
  footer_zh: v.footer_zh,
  registration_label: v.registration_label,
  registration_url: v.registration_url,
});
const codeFor = async (response: Response) => {
  try {
    const code = (await response.json()).error_code;
    return [
      "branding_invalid",
      "branding_image_invalid",
      "branding_contrast",
      "branding_conflict",
    ].includes(code)
      ? code
      : "branding_unavailable";
  } catch {
    return "branding_unavailable";
  }
};
const readable = (hex: string) => {
  const rgb = [1, 3, 5].map((i) => {
    const n = parseInt(hex.slice(i, i + 2), 16) / 255;
    return n <= 0.04045 ? n / 12.92 : ((n + 0.055) / 1.055) ** 2.4;
  });
  return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722 > 0.179 ? "#000000" : "#ffffff";
};

export default function BrandingPage() {
  const { t, i18n } = useTranslation();
  const colorID = useId();
  const { accessToken, setAccessToken } = useAuth();
  const permissions = usePermissions();
  const brand = useBranding();
  const [configuration, setConfiguration] = useState<Configuration | null>(null),
    [draft, setDraft] = useState<Draft>(plain(defaults)),
    [audit, setAudit] = useState<Audit[]>([]),
    [total, setTotal] = useState(0),
    [offset, setOffset] = useState(0);
  const [busy, setBusy] = useState(false),
    [upload, setUpload] = useState(false),
    [loading, setLoading] = useState(true),
    [denied, setDenied] = useState(false),
    [error, setError] = useState(""),
    [saved, setSaved] = useState(false);
  const authorized = permissions.systemAllows("branding.manage");
  const request = useCallback(
    async (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      const response = await fetch(url, { ...init, headers, credentials: "same-origin" });
      if (response.status === 401) setAccessToken("");
      if (response.status === 403) setDenied(true);
      return response;
    },
    [accessToken, setAccessToken],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      setLoading(true);
      setError("");
      setSaved(false);
      try {
        const [config, history] = await Promise.all([
          request("/api/v1/settings/branding", { signal }),
          request("/api/v1/settings/branding/audit?offset=0&limit=10", { signal }),
        ]);
        if (!config.ok || !history.ok) throw Error("branding_unavailable");
        const [next, rows] = await Promise.all([config.json(), history.json()]);
        if (signal?.aborted) return;
        setConfiguration(next);
        setDraft(plain(next.settings));
        setAudit(rows.results);
        setTotal(rows.total);
        setOffset(0);
      } catch {
        if (!signal?.aborted) setError("branding_unavailable");
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [request],
  );
  useEffect(() => {
    if (!permissions.ready || !authorized) return;
    const controller = new AbortController();
    // Fetch the authoritative global revision when the permitted page opens.
    // eslint-disable-next-line react/set-state-in-effect
    void load(controller.signal);
    return () => controller.abort();
  }, [permissions.ready, authorized, load]);
  const dirty = useMemo(
    () =>
      configuration !== null &&
      JSON.stringify(draft) !== JSON.stringify(plain(configuration.settings)),
    [configuration, draft],
  );
  const change = (field: keyof Draft, value: string) => {
    setSaved(false);
    setDraft((previous) => ({ ...previous, [field]: value }));
  };
  async function prepare(event: ChangeEvent<HTMLInputElement>, kind: ImageKind) {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (!file) return;
    setError("");
    setSaved(false);
    if (file.size > (kind === "login_image" ? 2 * 1024 * 1024 : 512 * 1024) || file.size === 0) {
      setError("branding_image_invalid");
      return;
    }
    setUpload(true);
    try {
      const data = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onerror = reject;
        reader.onload = () => resolve(String(reader.result).split(",")[1]);
        reader.readAsDataURL(file);
      });
      const response = await request("/api/v1/settings/branding/prepare-image", {
        method: "POST",
        body: JSON.stringify({ kind, data }),
      });
      if (!response.ok) throw Error(await codeFor(response));
      const prepared = await response.json();
      change(kind, prepared.data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "branding_image_invalid");
    } finally {
      setUpload(false);
    }
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!dirty || busy || upload) return;
    setBusy(true);
    setError("");
    setSaved(false);
    try {
      const response = await request("/api/v1/settings/branding", {
        method: "PUT",
        body: JSON.stringify(draft),
      });
      if (!response.ok) throw Error(await codeFor(response));
      const next = (await response.json()) as Branding;
      setConfiguration((previous) => (previous ? { ...previous, settings: next } : null));
      setDraft(plain(next));
      await brand.notify();
      const history = await request("/api/v1/settings/branding/audit?offset=0&limit=10");
      if (history.ok) {
        const rows = await history.json();
        setAudit(rows.results);
        setTotal(rows.total);
        setOffset(0);
      }
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "branding_unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function page(next: number) {
    setBusy(true);
    setError("");
    try {
      const response = await request(`/api/v1/settings/branding/audit?offset=${next}&limit=10`);
      if (!response.ok) throw Error();
      const rows = await response.json();
      setAudit(rows.results);
      setTotal(rows.total);
      setOffset(next);
    } catch {
      setError("branding_unavailable");
    } finally {
      setBusy(false);
    }
  }
  const zh = i18n.language.startsWith("zh"),
    name = zh ? draft.name_zh : draft.name_en;
  const palette =
    configuration?.themes.find((option) => option.id === draft.theme)?.colors || defaults.colors;
  const image = (kind: ImageKind) =>
    draft[kind] !== undefined
      ? draft[kind]
        ? `data:image/png;base64,${draft[kind]}`
        : ""
      : configuration?.settings[slots[kind]]
        ? `/api/v1/branding/images/${configuration.settings[slots[kind]]}`
        : "";
  const accent = /^#[0-9a-f]{6}$/i.test(draft.accent) ? draft.accent : defaults.accent;
  const previewStyle = {
    background: palette.bg,
    color: palette.text,
    borderColor: palette.border,
    "--preview-accent": accent,
    "--preview-accent-text": readable(accent),
  } as CSSProperties;
  if (!permissions.ready) return <p role="status">{t("branding.loading")}</p>;
  if (denied || !authorized)
    return (
      <section className="branding-page">
        <h1>{t("branding.title")}</h1>
        <p role="alert">{t("branding.denied")}</p>
      </section>
    );
  return (
    <section className="branding-page">
      <header>
        <div>
          <h1>{t("branding.title")}</h1>
          <p>{t("branding.scope")}</p>
        </div>
        <button
          className="button-secondary"
          disabled={busy || upload || loading}
          onClick={() => void load()}
        >
          {t("branding.reload")}
        </button>
      </header>
      {error && (
        <p role="alert">
          {t(
            `branding.errors.${["branding_invalid", "branding_image_invalid", "branding_contrast", "branding_conflict"].includes(error) ? error : "branding_unavailable"}`,
          )}
        </p>
      )}
      {saved && <p role="status">{t("branding.saved")}</p>}
      {loading && <p role="status">{t("branding.loading")}</p>}
      {configuration && (
        <form onSubmit={save}>
          <fieldset disabled={busy || upload || loading}>
            <legend>{t("branding.identity")}</legend>
            <div className="branding-fields">
              <label>
                {t("branding.nameEN")}
                <input
                  required
                  maxLength={128}
                  value={draft.name_en}
                  onChange={(e) => change("name_en", e.target.value)}
                />
              </label>
              <label>
                {t("branding.nameZH")}
                <input
                  required
                  maxLength={128}
                  value={draft.name_zh}
                  onChange={(e) => change("name_zh", e.target.value)}
                />
              </label>
              <label>
                {t("branding.theme")}
                <select
                  value={draft.theme}
                  onChange={(e) => {
                    const theme = e.target.value;
                    setDraft((previous) => ({
                      ...previous,
                      theme,
                      accent:
                        configuration.themes.find((option) => option.id === theme)?.colors.accent ||
                        previous.accent,
                    }));
                    setSaved(false);
                  }}
                >
                  {configuration.themes.map((option) => (
                    <option key={option.id} value={option.id}>
                      {t(`branding.themes.${option.id}`)}
                    </option>
                  ))}
                </select>
              </label>
              <div className="branding-color-field">
                <label htmlFor={colorID}>{t("branding.accent")}</label>
                <div>
                  <input
                    id={colorID}
                    required
                    pattern="#[0-9a-fA-F]{6}"
                    maxLength={7}
                    value={draft.accent}
                    onChange={(e) => change("accent", e.target.value)}
                    title={t("branding.hexHelp")}
                  />
                  <input
                    type="color"
                    value={accent}
                    aria-label={t("branding.accentPicker")}
                    onChange={(e) => change("accent", e.target.value)}
                  />
                </div>
              </div>
            </div>
            <p id="branding-image-help">{t("branding.imageHelp")}</p>
            <div className="branding-fields branding-copy-fields">
              {(
                [
                  "login_title_en",
                  "login_title_zh",
                  "footer_en",
                  "footer_zh",
                  "registration_label",
                  "registration_url",
                ] as const
              ).map((field) => (
                <label key={field}>
                  {t(`branding.fields.${field}`)}
                  <input
                    type={field === "registration_url" ? "url" : "text"}
                    maxLength={
                      field === "registration_url"
                        ? 1024
                        : field.startsWith("footer")
                          ? 320
                          : field === "registration_label"
                            ? 160
                            : 128
                    }
                    value={draft[field]}
                    onChange={(event) => change(field, event.target.value)}
                  />
                </label>
              ))}
            </div>
            <div className="branding-fields">
              {(["logo", "icon", "mark", "login_image"] as const).map((kind) => (
                <div className="branding-image-field" key={kind}>
                  <label>
                    {t(`branding.${kind}`)}
                    <input
                      type="file"
                      accept="image/png,image/jpeg"
                      aria-describedby="branding-image-help"
                      onChange={(e) => void prepare(e, kind)}
                    />
                  </label>
                  <button
                    type="button"
                    className="button-secondary"
                    disabled={!image(kind)}
                    onClick={() => change(kind, "")}
                  >
                    {t(`branding.${clearLabels[kind]}`)}
                  </button>
                </div>
              ))}
            </div>
            <div className="branding-actions">
              <button type="submit" className="button-primary" disabled={!dirty}>
                {t("branding.save")}
              </button>
              <button
                type="button"
                className="button-secondary"
                onClick={() => {
                  setDraft({
                    ...plain(defaults),
                    revision: draft.revision,
                    logo: "",
                    icon: "",
                    mark: "",
                    login_image: "",
                  });
                  setSaved(false);
                }}
              >
                {t("branding.defaults")}
              </button>
            </div>
          </fieldset>
          {upload && <p role="status">{t("branding.preparing")}</p>}
          <aside
            className="branding-preview"
            style={previewStyle}
            aria-label={t("branding.preview")}
          >
            <h2>{t("branding.preview")}</h2>
            <div className="branding-preview-header" style={{ background: palette.panel }}>
              {image("logo") ? (
                <img src={image("logo")} alt={name || t("branding.preview")} />
              ) : (
                <strong>{name || t("branding.preview")}</strong>
              )}
              {image("icon") && (
                <img
                  className="branding-icon-preview"
                  src={image("icon")}
                  alt={t("branding.iconPreview")}
                />
              )}
            </div>
            <p>{t("branding.previewHelp")}</p>
            {(draft.login_title_en || draft.login_title_zh) && (
              <h3>{zh ? draft.login_title_zh : draft.login_title_en}</h3>
            )}
            {image("mark") && (
              <img
                className="branding-icon-preview"
                src={image("mark")}
                alt={t("branding.markPreview")}
              />
            )}
            {image("login_image") && (
              <img
                className="branding-login-preview"
                src={image("login_image")}
                alt={t("branding.loginPreview")}
              />
            )}
            {(draft.footer_en || draft.footer_zh) && (
              <p>{zh ? draft.footer_zh : draft.footer_en}</p>
            )}
            {draft.registration_label && <p>{draft.registration_label}</p>}
            <span className="branding-accent-example">{t("branding.accentExample")}</span>
          </aside>
        </form>
      )}
      <section aria-labelledby="branding-audit-title">
        <h2 id="branding-audit-title">{t("branding.audit")}</h2>
        <div className="branding-audit">
          <table>
            <thead>
              <tr>
                {["at", "actor", "change", "revision"].map((key) => (
                  <th scope="col" key={key}>
                    {t(`branding.columns.${key}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {audit.map((row) => (
                <tr key={row.after.revision}>
                  <td>
                    {new Intl.DateTimeFormat(i18n.language, {
                      dateStyle: "short",
                      timeStyle: "medium",
                    }).format(new Date(row.at))}
                  </td>
                  <td>{row.actor}</td>
                  <td>
                    {zh ? row.before.name_zh : row.before.name_en} →{" "}
                    {zh ? row.after.name_zh : row.after.name_en} ·{" "}
                    {t(`branding.themes.${row.after.theme}`)}
                    <br />
                    {t("branding.accent")}: {row.after.accent}
                    {row.before.logo_digest !== row.after.logo_digest && (
                      <div>{t("branding.logoChanged")}</div>
                    )}
                    {row.before.icon_digest !== row.after.icon_digest && (
                      <div>{t("branding.iconChanged")}</div>
                    )}
                    {row.before.mark_digest !== row.after.mark_digest && (
                      <div>{t("branding.markChanged")}</div>
                    )}
                    {row.before.login_digest !== row.after.login_digest && (
                      <div>{t("branding.loginChanged")}</div>
                    )}
                  </td>
                  <td>
                    {row.before.revision} → {row.after.revision}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {audit.length === 0 && <p>{t("branding.noAudit")}</p>}
        <div className="branding-actions">
          <button
            disabled={busy || offset === 0}
            onClick={() => void page(Math.max(0, offset - 10))}
          >
            {t("branding.previous")}
          </button>
          <span>{t("branding.total", { count: total })}</span>
          <button disabled={busy || offset + 10 >= total} onClick={() => void page(offset + 10)}>
            {t("branding.next")}
          </button>
        </div>
      </section>
    </section>
  );
}
