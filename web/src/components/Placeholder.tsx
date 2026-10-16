import { useTranslation } from "react-i18next";
import type { ReactNode } from "react";

type PlaceholderProps = {
  title: string;
  hints?: ReactNode[];
};

export default function Placeholder({ title, hints }: PlaceholderProps) {
  const { t } = useTranslation();

  return (
    <div className="placeholder">
      <h2>{title}</h2>
      <p>{t("placeholder.skeleton")}</p>
      {hints && (
        <ul>
          {hints.map((h, i) => (
            <li key={i}>{h}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
