import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { Request, WorkflowRun, PlaybookStep } from "./playbooks";
import "../i18n/locales/features/playbooks/register";
import "./playbooks.css";
type Output = {
  result: {
    rc: number;
    stdout: string;
    stderr: string;
    changed: boolean;
    failed: boolean;
    skipped: boolean;
  };
  extra?: Record<string, unknown>;
};
export default function PlaybookRunDetails({
  run,
  request,
  onJob,
}: {
  run: WorkflowRun;
  request: Request;
  onJob: (id: string) => void;
}) {
  const { t, i18n } = useTranslation(),
    life = useRef<AbortController | null>(null);
  const [output, setOutput] = useState<Output | null>(null),
    [source, setSource] = useState<Record<string, string> | null>(null),
    [file, setFile] = useState("main.yml"),
    [error, setError] = useState(false),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    const ctl = new AbortController();
    life.current = ctl;
    return () => ctl.abort();
  }, [run.id]);
  const read = async (asset: string, step: PlaybookStep) => {
    if (!life.current) return;
    setBusy(true);
    setError(false);
    setOutput(null);
    try {
      const r = await request(
        `/api/v1/ops/runs/${encodeURIComponent(run.id)}/steps/${encodeURIComponent(asset)}/${encodeURIComponent(step.id)}`,
        { signal: life.current.signal },
      );
      if (!r.ok) throw Error();
      const v = (await r.json()) as Output;
      if (!life.current.signal.aborted) setOutput(v);
    } catch {
      if (!life.current.signal.aborted) setError(true);
    } finally {
      setBusy(false);
    }
  };
  const readSource = async () => {
    if (!life.current) return;
    setBusy(true);
    setError(false);
    try {
      const r = await request(`/api/v1/ops/runs/${encodeURIComponent(run.id)}/program`, {
        signal: life.current.signal,
      });
      if (!r.ok) throw Error();
      const v = (await r.json()) as { files: Record<string, string> };
      if (!life.current.signal.aborted) {
        setSource(v.files);
        setFile("main.yml");
      }
    } catch {
      if (!life.current.signal.aborted) setError(true);
    } finally {
      setBusy(false);
    }
  };
  const download = () => {
    if (!source) return;
    const link = document.createElement("a"),
      url = URL.createObjectURL(
        new Blob([JSON.stringify({ files: source }, null, 2)], { type: "application/json" }),
      );
    link.href = url;
    link.download = `${run.id}-workspace.json`;
    link.click();
    URL.revokeObjectURL(url);
  };
  return (
    <section className="playbook-run" aria-label={t("playbooks.steps")}>
      <h4>{t("playbooks.steps")}</h4>
      {run.error_code && (
        <p role="status">
          {t("playbooks.errors." + run.error_code, { defaultValue: t("operations.dispatchError") })}
        </p>
      )}
      <p>
        {t("playbooks.revision")}: {run.playbook_revision} · {t("playbooks.trigger")}:{" "}
        {t("playbooks.triggers." + (run.trigger || "schedule"))} · {t("playbooks.actor")}:{" "}
        {run.triggered_by?.name || run.triggered_by?.id || "—"}
      </p>
      <p>
        {t("playbooks.digest")}: <code>{run.program_id}</code>
      </p>
      {run.deadline && (
        <p>
          {t("playbooks.deadline")}:{" "}
          <time dateTime={run.deadline}>
            {new Date(run.deadline).toLocaleString(i18n.language)}
          </time>
        </p>
      )}
      {run.error_code && (
        <p role="status">
          {t("playbooks.errors." + run.error_code, { defaultValue: t("operations.dispatchError") })}
        </p>
      )}
      <p>{t("playbooks.digestHint")}</p>
      <button type="button" disabled={busy} onClick={() => void readSource()}>
        {t("playbooks.sourceSnapshot")}
      </button>
      {source && (
        <details open>
          <summary>{t("playbooks.source")}</summary>
          <p>{t("playbooks.sourceReadHint")}</p>
          <label>
            {t("playbooks.files")}
            <select value={file} onChange={(e) => setFile(e.target.value)}>
              {Object.keys(source)
                .sort()
                .map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
            </select>
          </label>
          <pre className="playbooks-code">{source[file]}</pre>
          <button type="button" onClick={download}>
            {t("playbooks.downloadSource")}
          </button>
        </details>
      )}
      {error && <p role="alert">{t("playbooks.outputUnavailable")}</p>}
      {run.items.map((item) => (
        <section key={item.asset_id} aria-label={item.asset_id}>
          <h5>
            <code>{item.asset_id}</code> ·{" "}
            {t("playbooks.states." + item.state, { defaultValue: t("operations.dispatchError") })}
          </h5>
          {!item.steps?.length && <p>{t("playbooks.noSteps")}</p>}
          <div className="playbooks-scroll">
            <table aria-label={t("playbooks.steps")}>
              <thead>
                <tr>
                  {["name", "module", "iteration", "attempt"].map((k) => (
                    <th key={k} scope="col">
                      {t("playbooks." + k)}
                    </th>
                  ))}
                  <th scope="col">{t("jobs.status")}</th>
                  <th scope="col">{t("playbooks.changed")}</th>
                  <th scope="col">{t("playbooks.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {item.steps?.map((step) => (
                  <tr key={step.id}>
                    <td>{step.name}</td>
                    <td>
                      <code>{step.module}</code>
                    </td>
                    <td>{step.iteration + 1}</td>
                    <td>{step.attempt + 1}</td>
                    <td>
                      {t("playbooks.states." + step.state, {
                        defaultValue: t("operations.dispatchError"),
                      })}
                      {step.error_code && (
                        <p>
                          {t("playbooks.errors." + step.error_code, {
                            defaultValue: t("operations.dispatchError"),
                          })}
                        </p>
                      )}
                      {step.ignored && <p>{t("playbooks.ignored")}</p>}
                      {step.review_id && <code>{step.review_id}</code>}
                    </td>
                    <td>{t(step.changed ? "playbooks.changed" : "playbooks.unchanged")}</td>
                    <td>
                      {step.final && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void read(item.asset_id, step)}
                        >
                          {t("playbooks.openStep")}
                        </button>
                      )}
                      {step.job_id && (
                        <button type="button" onClick={() => onJob(step.job_id!)}>
                          {t("operations.openJob")}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
      {output && (
        <section aria-label={t("playbooks.stepOutput")}>
          <h5>{t("playbooks.stepOutput")}</h5>
          <p>
            {t("playbooks.rc")}: {output.result.rc} ·{" "}
            {t(output.result.changed ? "playbooks.changed" : "playbooks.unchanged")}
          </p>
          <h6>{t("playbooks.stdout")}</h6>
          <pre>{output.result.stdout}</pre>
          <h6>{t("playbooks.stderr")}</h6>
          <pre>{output.result.stderr}</pre>
          {output.extra && (
            <details>
              <summary>{t("playbooks.details")}</summary>
              <pre>{JSON.stringify(output.extra, null, 2)}</pre>
            </details>
          )}
        </section>
      )}
    </section>
  );
}
