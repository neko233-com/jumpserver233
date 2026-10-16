import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import SSHTerminalDialog from "./SSHTerminalDialog";

type Pod = { name: string; uid: string; containers: string[] };
type Selection = { namespace: string; pod: string; container: string };
type Props = { assetId: string; assetName: string; accessToken: string; onClose: () => void };
export default function KubernetesTerminalDialog(props: Props) {
  const { t } = useTranslation();
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [namespace, setNamespace] = useState("");
  const [pods, setPods] = useState<Pod[]>([]);
  const [pod, setPod] = useState("");
  const [container, setContainer] = useState("");
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [refresh, setRefresh] = useState(0);
  function resetList() {
    setLoading(true);
    setFailed(false);
    setPods([]);
    setPod("");
    setContainer("");
  }
  useEffect(() => {
    const controller = new AbortController();
    const headers = new Headers();
    if (props.accessToken) headers.set("Authorization", `Bearer ${props.accessToken}`);
    void fetch(
      `/api/v1/assets/${encodeURIComponent(props.assetId)}/kubernetes/pods?namespace=${encodeURIComponent(namespace)}`,
      { headers, signal: controller.signal },
    )
      .then(async (response) => {
        if (!response.ok) throw new Error("cluster request failed");
        const data = (await response.json()) as {
          namespaces: string[];
          namespace: string;
          pods: Pod[];
        };
        if (controller.signal.aborted) return;
        setNamespaces(data.namespaces);
        setPods(data.pods);
        setPod(data.pods[0]?.name ?? "");
        setContainer(data.pods[0]?.containers[0] ?? "");
        setLoading(false);
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setFailed(true);
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [props.assetId, props.accessToken, namespace, refresh]);
  const currentNamespace = namespace || namespaces[0] || "";
  if (selection) return <SSHTerminalDialog {...props} kubernetesSelection={selection} />;
  return (
    <div className="asset-modal-backdrop">
      <section
        className="asset-modal kubernetes-target-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="kubernetes-target-title"
      >
        <h2 id="kubernetes-target-title">
          {t("kubernetes.selectTitle", { name: props.assetName })}
        </h2>
        <p>{t("kubernetes.hint")}</p>
        <label>
          {t("kubernetes.namespace")}
          <select
            value={currentNamespace}
            aria-label={t("kubernetes.namespace")}
            disabled={loading}
            onChange={(e) => {
              resetList();
              setNamespace(e.target.value);
            }}
          >
            {namespaces.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("kubernetes.pod")}
          <select
            value={pod}
            aria-label={t("kubernetes.pod")}
            disabled={loading}
            onChange={(e) => {
              setPod(e.target.value);
              setContainer(pods.find((p) => p.name === e.target.value)?.containers[0] ?? "");
            }}
          >
            {pods.map((p) => (
              <option key={p.uid} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("kubernetes.container")}
          <select
            value={container}
            aria-label={t("kubernetes.container")}
            disabled={loading}
            onChange={(e) => setContainer(e.target.value)}
          >
            {pods
              .find((p) => p.name === pod)
              ?.containers.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
          </select>
        </label>
        {loading && <p role="status">{t("kubernetes.loading")}</p>}
        {failed && <p role="alert">{t("kubernetes.loadFailed")}</p>}
        {!loading && !failed && !pods.length && <p role="status">{t("kubernetes.empty")}</p>}
        <div className="asset-modal-actions">
          <button type="button" className="button-secondary" onClick={props.onClose}>
            {t("terminal.close")}
          </button>
          <button
            type="button"
            className="button-secondary"
            disabled={loading}
            onClick={() => {
              resetList();
              setRefresh((v) => v + 1);
            }}
          >
            {t("assets.refresh")}
          </button>
          <button
            type="button"
            className="button-primary"
            disabled={loading || failed || !pod || !container}
            onClick={() => setSelection({ namespace: currentNamespace, pod, container })}
          >
            {t("assets.connect")}
          </button>
        </div>
      </section>
    </div>
  );
}
