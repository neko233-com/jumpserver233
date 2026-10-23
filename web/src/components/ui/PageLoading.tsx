import { useTranslation } from "react-i18next";

export default function PageLoading() {
  const { t } = useTranslation();
  return (
    <div className="page-loading" role="status" aria-label={t("placeholder.skeleton")}>
      <span className="console-sr-only">{t("placeholder.skeleton")}</span>
      <div className="page-loading-title" />
      <div className="page-loading-line" />
      <div className="page-loading-table">
        {[0, 1, 2, 3].map((row) => (
          <div key={row} />
        ))}
      </div>
    </div>
  );
}
