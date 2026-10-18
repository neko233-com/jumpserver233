import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { usePermissions } from "../auth/usePermissions";
import { toggleLang } from "../i18n";
import {
  workspaceURL,
  type Request,
  type Playbook,
  type PlaybookDetail,
  type Issue,
} from "./playbooks";
import "../i18n/locales/features/playbooks/register";
import "./playbooks.css";

type Props = { request: Request; onChanged: () => void; onChoose: (book: Playbook) => void };
type Event = {
  id: string;
  at: string;
  actor: { id: string; name: string };
  action: string;
  revision: number;
  program_id: string;
  visibility: string;
};
export default function PlaybookWorkspaces({ request, onChanged, onChoose }: Props) {
  const { t, i18n } = useTranslation(),
    { userID } = usePermissions();
  const [books, setBooks] = useState<Playbook[]>([]),
    [offset, setOffset] = useState(0),
    [total, setTotal] = useState(0),
    [version, setVersion] = useState(0),
    [error, setError] = useState(false),
    [editing, setEditing] = useState<Playbook | "new" | null>(null);
  useEffect(() => {
    const ctl = new AbortController();
    void request(`/api/v1/ops/playbooks?offset=${offset}&limit=25`, { signal: ctl.signal })
      .then((r) => {
        if (!r.ok) throw Error();
        return r.json() as Promise<{ results: Playbook[]; total: number }>;
      })
      .then((v) => {
        if (!ctl.signal.aborted) {
          setBooks(v.results);
          setTotal(v.total);
          setError(false);
          if (offset > 0 && offset >= v.total)
            setOffset(Math.floor(Math.max(0, v.total - 1) / 25) * 25);
        }
      })
      .catch(() => {
        if (!ctl.signal.aborted) setError(true);
      });
    return () => ctl.abort();
  }, [request, offset, version]);
  const remove = async (book: Playbook) => {
    if (!confirm(t("playbooks.deleteConfirm"))) return;
    try {
      const r = await request(workspaceURL(book.id) + "?revision=" + book.revision, {
        method: "DELETE",
      });
      if (!r.ok) throw Error();
      setVersion((v) => v + 1);
      onChanged();
    } catch {
      setError(true);
    }
  };
  return (
    <details className="playbooks-manager">
      <summary>{t("playbooks.title")}</summary>
      <p>{t("playbooks.description")}</p>
      <button type="button" onClick={() => setEditing("new")}>
        {t("playbooks.new")}
      </button>
      {error && <p role="alert">{t("playbooks.unavailable")}</p>}
      <div className="playbooks-scroll">
        <table aria-label={t("playbooks.list")}>
          <thead>
            <tr>
              {["name", "owner", "visibility", "revision", "tasks", "updated", "actions"].map(
                (k) => (
                  <th key={k} scope="col">
                    {t("playbooks." + k)}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {books.map((b) => (
              <tr key={b.id}>
                <td>{b.name}</td>
                <td>{b.owner}</td>
                <td>{t("playbooks." + b.visibility)}</td>
                <td>{b.revision}</td>
                <td>{b.task_count}</td>
                <td>{new Date(b.updated_at).toLocaleString(i18n.language)}</td>
                <td>
                  <button type="button" onClick={() => setEditing(b)}>
                    {t(b.owner_id === userID ? "playbooks.edit" : "playbooks.read")}
                  </button>
                  <button type="button" onClick={() => onChoose(b)}>
                    {t("playbooks.choose")}
                  </button>
                  {b.owner_id === userID && (
                    <button type="button" onClick={() => void remove(b)}>
                      {t("playbooks.delete")}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!books.length && <p>{t("playbooks.empty")}</p>}
      <nav aria-label={t("playbooks.pages")} className="playbooks-actions">
        <button
          type="button"
          disabled={!offset}
          onClick={() => setOffset((v) => Math.max(0, v - 25))}
        >
          {t("jobs.previous")}
        </button>
        <span>
          {total ? offset + 1 : 0}–{Math.min(offset + 25, total)} / {total}
        </span>
        <button
          type="button"
          disabled={offset + 25 >= total}
          onClick={() => setOffset((v) => v + 25)}
        >
          {t("jobs.next")}
        </button>
      </nav>
      {editing && (
        <WorkspaceEditor
          book={editing === "new" ? null : editing}
          request={request}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            setVersion((v) => v + 1);
            onChanged();
          }}
        />
      )}
    </details>
  );
}

function WorkspaceEditor({
  book,
  request,
  onClose,
  onSaved,
}: {
  book: Playbook | null;
  request: Request;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { t } = useTranslation(),
    { userID, allows } = usePermissions(),
    dialog = useRef<HTMLDialogElement>(null),
    life = useRef<AbortController | null>(null),
    sourceKey = useRef("");
  const [name, setName] = useState(book?.name || ""),
    [description, setDescription] = useState(book?.description || ""),
    [visibility, setVisibility] = useState(book?.visibility || "private"),
    [revision, setRevision] = useState(book?.revision || 0),
    [digest, setDigest] = useState(book?.program_id || ""),
    [files, setFiles] = useState<Record<string, string>>({
      "main.yml": t("playbooks.example", { skipInterpolation: true }),
    }),
    [filename, setFilename] = useState("main.yml"),
    [newFile, setNewFile] = useState(""),
    [busy, setBusy] = useState(Boolean(book)),
    [ready, setReady] = useState(!book),
    [error, setError] = useState(""),
    [issue, setIssue] = useState<Issue | null>(null),
    [validation, setValidation] = useState<{ key: string; count: number; steps: number } | null>(
      null,
    ),
    [events, setEvents] = useState<Event[]>([]),
    [eventOffset, setEventOffset] = useState(0),
    [eventTotal, setEventTotal] = useState(0),
    [eventVersion, setEventVersion] = useState(0),
    [modules, setModules] = useState<string[]>([]);
  const currentSourceKey = JSON.stringify(files);
  useEffect(() => {
    sourceKey.current = currentSourceKey;
  }, [currentSourceKey]);
  const editable = !book || book.owner_id === userID;
  useEffect(() => {
    const ctl = new AbortController();
    life.current = ctl;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const element = dialog.current;
    element?.showModal();
    return () => {
      ctl.abort();
      element?.close();
      if (previous?.isConnected) previous.focus();
    };
  }, []);
  const reload = useCallback(async () => {
    if (!book || !life.current) return;
    setBusy(true);
    setError("");
    try {
      const r = await request(workspaceURL(book.id), { signal: life.current.signal });
      if (!r.ok) throw Error();
      const v = (await r.json()) as PlaybookDetail;
      if (life.current.signal.aborted) return;
      setName(v.name);
      setDescription(v.description);
      setVisibility(v.visibility);
      setRevision(v.revision);
      setDigest(v.program_id);
      setFiles(v.files);
      setFilename("main.yml");
      setReady(true);
      setIssue(null);
      setValidation(null);
      setEventVersion((x) => x + 1);
    } catch {
      if (!life.current.signal.aborted) {
        setReady(false);
        setFiles({});
        setEvents([]);
        setError("unavailable");
      }
    } finally {
      setBusy(false);
    }
  }, [book, request]);
  useEffect(() => {
    if (book) void reload();
  }, [book, reload]);
  useEffect(() => {
    const ctl = new AbortController();
    void request("/api/v1/ops/playbooks/capabilities", { signal: ctl.signal })
      .then((r) => {
        if (!r.ok) throw Error();
        return r.json() as Promise<{ modules: string[] }>;
      })
      .then((v) => {
        if (!ctl.signal.aborted) setModules(v.modules);
      })
      .catch(() => {});
    return () => ctl.abort();
  }, [request]);
  useEffect(() => {
    if (!book || !editable) return;
    const ctl = new AbortController();
    void request(workspaceURL(book.id) + `/events?offset=${eventOffset}&limit=20`, {
      signal: ctl.signal,
    })
      .then((r) => {
        if (!r.ok) throw Error();
        return r.json() as Promise<{ results: Event[]; total: number }>;
      })
      .then((v) => {
        if (!ctl.signal.aborted) {
          setEvents(v.results);
          setEventTotal(v.total);
        }
      })
      .catch(() => {
        if (!ctl.signal.aborted) setError("unavailable");
      });
    return () => ctl.abort();
  }, [book, editable, eventOffset, eventVersion, request]);
  const report = async (r: Response) => {
    if (r.status === 409) {
      setError("conflict");
      return;
    }
    if (r.status === 403) {
      setError("denied");
      return;
    }
    if (r.status === 400) {
      const v = (await r.json()) as { issue?: Issue };
      setIssue(v.issue || null);
      setError("invalid");
      return;
    }
    setError("unavailable");
  };
  const validate = async () => {
    if (!life.current) return;
    const key = sourceKey.current;
    setBusy(true);
    setError("");
    setIssue(null);
    try {
      const r = await request("/api/v1/ops/playbooks/validate", {
        method: "POST",
        body: JSON.stringify({ files }),
        signal: life.current.signal,
      });
      if (!r.ok) {
        await report(r);
        return;
      }
      const v = (await r.json()) as { tasks: unknown[]; max_steps: number };
      if (!life.current.signal.aborted && sourceKey.current === key)
        setValidation({ key, count: v.tasks.length, steps: v.max_steps });
    } catch {
      if (!life.current.signal.aborted) setError("unavailable");
    } finally {
      setBusy(false);
    }
  };
  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!life.current) return;
    setBusy(true);
    setError("");
    setIssue(null);
    try {
      const r = await request(book ? workspaceURL(book.id) : "/api/v1/ops/playbooks", {
        method: book ? "PUT" : "POST",
        body: JSON.stringify({ name, description, visibility, revision, files }),
        signal: life.current.signal,
      });
      if (!r.ok) {
        await report(r);
        return;
      }
      if (!life.current.signal.aborted) onSaved();
    } catch {
      if (!life.current.signal.aborted) setError("unavailable");
    } finally {
      setBusy(false);
    }
  };
  const add = () => {
    const value = newFile.trim();
    if (
      !/^[A-Za-z0-9_./-]+$/.test(value) ||
      value.startsWith("/") ||
      value.split("/").some((s) => s === ".." || s === "." || !s) ||
      files[value] !== undefined ||
      Object.keys(files).length >= 32
    ) {
      setError("fileInvalid");
      return;
    }
    setFiles((v) => ({ ...v, [value]: "" }));
    setFilename(value);
    setNewFile("");
    setError("");
  };
  const bytes = new TextEncoder().encode(Object.values(files).join("")).length;
  return (
    <dialog
      ref={dialog}
      className="playbooks-dialog"
      aria-labelledby="playbook-editor-title"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <header>
        <h2 id="playbook-editor-title">{t(book ? "playbooks.edit" : "playbooks.new")}</h2>
        <button type="button" onClick={() => void toggleLang()}>
          {t("sharing.language")}
        </button>
        <button type="button" onClick={onClose}>
          {t("playbooks.close")}
        </button>
      </header>
      <p>{t("playbooks.native")}</p>
      {modules.length > 0 && (
        <details>
          <summary>{t("playbooks.capabilities")}</summary>
          <ul>
            {modules.map((m) => (
              <li key={m}>
                <code>{m}</code> · {t("playbooks.modules." + m)}
              </li>
            ))}
          </ul>
        </details>
      )}
      {error && (
        <p role="alert">
          {t("playbooks." + error)}
          {issue && (
            <>
              <br />
              {t("playbooks.issue", {
                file: issue.file || "main.yml",
                line: issue.line || 0,
                column: issue.column || 0,
                code: issue.code || "",
                field: issue.field || "",
              })}
            </>
          )}
        </p>
      )}
      {validation?.key === currentSourceKey && (
        <p role="status">
          {t("playbooks.valid", { count: validation.count, steps: validation.steps })}
        </p>
      )}
      <p>
        {t("playbooks.revision")}: {revision} · {t("playbooks.digest")}:{" "}
        <code>{digest || "—"}</code>
      </p>
      <form onSubmit={(e) => void save(e)}>
        <fieldset disabled={!editable || busy || !ready}>
          <label>
            {t("playbooks.name")}
            <input
              required
              maxLength={100}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          <label>
            {t("playbooks.descriptionLabel")}
            <textarea
              rows={2}
              maxLength={2000}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </label>
          <label>
            {t("playbooks.visibility")}
            <select value={visibility} onChange={(e) => setVisibility(e.target.value)}>
              <option value="private">{t("playbooks.private")}</option>
              <option value="organization" disabled={!allows("playbooks.publish")}>
                {t("playbooks.organization")}
              </option>
            </select>
          </label>
          <p>{t("playbooks.publishHint")}</p>
          <label>
            {t("playbooks.files")}
            <select value={filename} onChange={(e) => setFilename(e.target.value)}>
              {Object.keys(files)
                .sort()
                .map((file) => (
                  <option key={file} value={file}>
                    {file}
                  </option>
                ))}
            </select>
          </label>
          <div className="playbooks-actions">
            <label>
              {t("playbooks.filename")}
              <input maxLength={128} value={newFile} onChange={(e) => setNewFile(e.target.value)} />
            </label>
            <button type="button" onClick={add}>
              {t("playbooks.addFile")}
            </button>
            <button
              type="button"
              disabled={filename === "main.yml"}
              onClick={() => {
                setFiles((previous) => {
                  const next = { ...previous };
                  delete next[filename];
                  return next;
                });
                setFilename("main.yml");
              }}
            >
              {t("playbooks.deleteFile")}
            </button>
          </div>
          <label>
            {t("playbooks.content")}
            <textarea
              className="playbooks-code"
              rows={18}
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="off"
              value={files[filename] || ""}
              onChange={(e) => {
                setFiles((v) => ({ ...v, [filename]: e.target.value }));
                setError("");
                setIssue(null);
              }}
            />
          </label>
          <p>
            {t("playbooks.limits")} · {t("playbooks.bytes", { count: bytes })}
          </p>
        </fieldset>
        <div className="playbooks-actions">
          <button type="button" disabled={busy || !ready} onClick={() => void validate()}>
            {t("playbooks.validate")}
          </button>
          {editable && (
            <button type="submit" disabled={busy || !ready || bytes > 65536}>
              {t("playbooks.save")}
            </button>
          )}
          {book && (
            <button type="button" disabled={busy} onClick={() => void reload()}>
              {t("playbooks.reload")}
            </button>
          )}
        </div>
      </form>
      {book && editable && (
        <>
          <h3>{t("playbooks.events")}</h3>
          <p>{t("playbooks.before")}</p>
          <div className="playbooks-scroll">
            <table aria-label={t("playbooks.events")}>
              <thead>
                <tr>
                  {["updated", "owner", "actions", "revision", "digest", "visibility"].map((k) => (
                    <th key={k} scope="col">
                      {t("playbooks." + k)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((v) => (
                  <tr key={v.id}>
                    <td>{v.at}</td>
                    <td>{v.actor.name || v.actor.id}</td>
                    <td>{t("playbooks.eventAction." + v.action)}</td>
                    <td>{v.revision}</td>
                    <td>
                      <code>{v.program_id}</code>
                    </td>
                    <td>{t("playbooks." + v.visibility)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <nav className="playbooks-actions" aria-label={t("playbooks.events")}>
            <button
              type="button"
              disabled={!eventOffset}
              onClick={() => setEventOffset((v) => Math.max(0, v - 20))}
            >
              {t("jobs.previous")}
            </button>
            <span>
              {eventTotal ? eventOffset + 1 : 0}–{Math.min(eventOffset + 20, eventTotal)} /{" "}
              {eventTotal}
            </span>
            <button
              type="button"
              disabled={eventOffset + 20 >= eventTotal}
              onClick={() => setEventOffset((v) => v + 20)}
            >
              {t("jobs.next")}
            </button>
          </nav>
        </>
      )}
    </dialog>
  );
}
