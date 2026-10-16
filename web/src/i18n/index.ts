import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./locales/en";
import zhCN from "./locales/zh-CN";

const STORAGE_KEY = "jms233.lang";
export type Lang = "zh-CN" | "en";

function detectLang(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "zh-CN" || saved === "en") return saved;
  } catch {
    // localStorage unavailable (private mode); fall through to navigator
  }
  return navigator.language.toLowerCase().startsWith("zh") ? "zh-CN" : "en";
}

const initialLang = detectLang();
document.documentElement.lang = initialLang;

i18n.use(initReactI18next).init({
  resources: {
    "zh-CN": { translation: zhCN },
    en: { translation: en },
  },
  lng: initialLang,
  fallbackLng: "zh-CN",
  interpolation: { escapeValue: false },
});

i18n.on("languageChanged", (lng) => {
  try {
    localStorage.setItem(STORAGE_KEY, lng);
  } catch {
    // best effort persistence
  }
  document.documentElement.lang = lng;
});

export function toggleLang(): Lang {
  const next: Lang = i18n.language === "zh-CN" ? "en" : "zh-CN";
  void i18n.changeLanguage(next);
  return next;
}

export default i18n;
