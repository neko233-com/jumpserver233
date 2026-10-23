import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext";
import Icon from "./Icon";

export type SearchDestination = { to: string; label: string; end?: boolean };
type SearchAsset = {
  id: string;
  name: string;
  host: string;
  remark?: string;
  permissions?: string[];
};

export default function QuickSearch({
  destinations,
  onClose,
}: {
  destinations: SearchDestination[];
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [assets, setAssets] = useState<SearchAsset[]>([]);
  const [state, setState] = useState("loading");
  const [selected, setSelected] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const headingID = useId(),
    listID = useId();
  useEffect(() => {
    const controller = new AbortController();
    input.current?.focus();
    fetch("/api/v1/assets", {
      headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) throw Error("Search unavailable");
        const result = (await response.json()) as SearchAsset[];
        if (!controller.signal.aborted) {
          setAssets(result);
          setState("ready");
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) setState("failed");
      });
    return () => controller.abort();
  }, [accessToken]);
  const needle = query.trim().toLocaleLowerCase();
  const pages = destinations.filter((d) => d.label.toLocaleLowerCase().includes(needle));
  const hosts = needle
    ? assets
        .filter((a) => `${a.name} ${a.host} ${a.remark || ""}`.toLocaleLowerCase().includes(needle))
        .slice(0, 20)
    : [];
  const results = [
    ...hosts.map((a) => ({
      to: `/console?asset_id=${encodeURIComponent(a.id)}`,
      label: a.name,
      detail: a.host,
      host: true,
    })),
    ...pages.map((d) => ({ ...d, detail: t("ui.search.page"), host: false })),
  ];
  const index = Math.min(selected, Math.max(0, results.length - 1));
  const choose = (destination: string) => {
    onClose();
    navigate(destination);
  };
  const onKeyDown = (event: KeyboardEvent) => {
    if (event.nativeEvent.isComposing) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      onClose();
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const next = results.length
        ? (index + (event.key === "ArrowDown" ? 1 : -1) + results.length) % results.length
        : 0;
      setSelected(next);
      document.getElementById(`${listID}-${next}`)?.scrollIntoView({ block: "nearest" });
    }
    if (event.key === "Enter" && results[index]) {
      event.preventDefault();
      choose(results[index].to);
    }
  };
  return createPortal(
    <div
      className="quick-search-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <section
        className="quick-search"
        role="dialog"
        aria-modal="true"
        aria-labelledby={headingID}
        onKeyDown={onKeyDown}
      >
        <h2 className="console-sr-only" id={headingID}>
          {t("ui.search.title")}
        </h2>
        <div className="quick-search-field">
          <Icon name="search" size={21} />
          <input
            ref={input}
            role="combobox"
            aria-autocomplete="list"
            aria-expanded="true"
            aria-controls={listID}
            aria-activedescendant={results.length ? `${listID}-${index}` : undefined}
            aria-label={t("ui.search.title")}
            placeholder={t("ui.search.placeholder")}
            value={query}
            maxLength={200}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelected(0);
            }}
          />
          <button
            type="button"
            className="icon-button"
            aria-label={t("ui.close")}
            onClick={onClose}
          >
            <Icon name="close" />
          </button>
        </div>
        <div
          className="quick-search-results"
          role="listbox"
          id={listID}
          aria-label={t("ui.search.results")}
        >
          {results.map((result, i) => (
            <div
              key={result.to}
              id={`${listID}-${i}`}
              role="option"
              aria-selected={index === i}
              className="quick-search-result"
              onMouseMove={() => setSelected(i)}
              onClick={() => choose(result.to)}
            >
              <Icon name={result.host ? "server" : "arrow"} />
              <span>
                <strong>{result.label}</strong>
                <small>{result.detail}</small>
              </span>
              <Icon name="chevron" size={14} />
            </div>
          ))}
          {!results.length && (
            <div className="ui-empty" role="status">
              <Icon name="search" size={28} />
              <strong>{t("ui.search.empty")}</strong>
              <span>{t("ui.search.emptyHint")}</span>
            </div>
          )}
        </div>
        <footer className="quick-search-footer">
          <span>{t("ui.search.keyboard")}</span>
          <span role="status">
            {state === "loading"
              ? t("ui.search.loading")
              : state === "failed"
                ? t("ui.search.failed")
                : t("ui.search.count", { count: results.length })}
          </span>
        </footer>
      </section>
    </div>,
    document.body,
  );
}
