// UI message catalogs, one per supported locale. Keys are dotted,
// stable identifiers; English is the source-of-truth catalog and the
// react-intl fallback (defaultLocale="en"), so a key missing from a
// translated catalog renders the English string rather than the raw
// key.
//
// This catalog intentionally covers the chrome that is rendered for
// every operator (layout, language switcher, tenant switcher). Feature
// screens adopt keys incrementally; until then they fall back to their
// existing inline English, which react-intl leaves untouched.

import type { Locale } from "./locales";

export type MessageKey =
  | "app.subtitle"
  | "topbar.tenant"
  | "topbar.tenant.loading"
  | "topbar.tenant.none"
  | "topbar.signOut"
  | "topbar.language";

type Catalog = Record<MessageKey, string>;

const en: Catalog = {
  "app.subtitle": "Gateway console",
  "topbar.tenant": "Tenant",
  "topbar.tenant.loading": "Loading tenants…",
  "topbar.tenant.none": "No tenants",
  "topbar.signOut": "Sign out",
  "topbar.language": "Language",
};

const zhHans: Catalog = {
  "app.subtitle": "网关控制台",
  "topbar.tenant": "租户",
  "topbar.tenant.loading": "正在加载租户…",
  "topbar.tenant.none": "无租户",
  "topbar.signOut": "退出登录",
  "topbar.language": "语言",
};

const zhHant: Catalog = {
  "app.subtitle": "閘道控制台",
  "topbar.tenant": "租戶",
  "topbar.tenant.loading": "正在載入租戶…",
  "topbar.tenant.none": "沒有租戶",
  "topbar.signOut": "登出",
  "topbar.language": "語言",
};

const ms: Catalog = {
  "app.subtitle": "Konsol Gerbang",
  "topbar.tenant": "Penyewa",
  "topbar.tenant.loading": "Memuatkan penyewa…",
  "topbar.tenant.none": "Tiada penyewa",
  "topbar.signOut": "Log keluar",
  "topbar.language": "Bahasa",
};

const id: Catalog = {
  "app.subtitle": "Konsol Gateway",
  "topbar.tenant": "Tenant",
  "topbar.tenant.loading": "Memuat tenant…",
  "topbar.tenant.none": "Tidak ada tenant",
  "topbar.signOut": "Keluar",
  "topbar.language": "Bahasa",
};

const th: Catalog = {
  "app.subtitle": "คอนโซลเกตเวย์",
  "topbar.tenant": "ผู้เช่า",
  "topbar.tenant.loading": "กำลังโหลดผู้เช่า…",
  "topbar.tenant.none": "ไม่มีผู้เช่า",
  "topbar.signOut": "ออกจากระบบ",
  "topbar.language": "ภาษา",
};

const vi: Catalog = {
  "app.subtitle": "Bảng điều khiển Gateway",
  "topbar.tenant": "Người thuê",
  "topbar.tenant.loading": "Đang tải người thuê…",
  "topbar.tenant.none": "Không có người thuê",
  "topbar.signOut": "Đăng xuất",
  "topbar.language": "Ngôn ngữ",
};

const ja: Catalog = {
  "app.subtitle": "ゲートウェイコンソール",
  "topbar.tenant": "テナント",
  "topbar.tenant.loading": "テナントを読み込み中…",
  "topbar.tenant.none": "テナントがありません",
  "topbar.signOut": "サインアウト",
  "topbar.language": "言語",
};

const ko: Catalog = {
  "app.subtitle": "게이트웨이 콘솔",
  "topbar.tenant": "테넌트",
  "topbar.tenant.loading": "테넌트 로드 중…",
  "topbar.tenant.none": "테넌트 없음",
  "topbar.signOut": "로그아웃",
  "topbar.language": "언어",
};

const ar: Catalog = {
  "app.subtitle": "وحدة تحكم البوابة",
  "topbar.tenant": "المستأجر",
  "topbar.tenant.loading": "جارٍ تحميل المستأجرين…",
  "topbar.tenant.none": "لا يوجد مستأجرون",
  "topbar.signOut": "تسجيل الخروج",
  "topbar.language": "اللغة",
};

const de: Catalog = {
  "app.subtitle": "Gateway-Konsole",
  "topbar.tenant": "Mandant",
  "topbar.tenant.loading": "Mandanten werden geladen…",
  "topbar.tenant.none": "Keine Mandanten",
  "topbar.signOut": "Abmelden",
  "topbar.language": "Sprache",
};

const fr: Catalog = {
  "app.subtitle": "Console de passerelle",
  "topbar.tenant": "Locataire",
  "topbar.tenant.loading": "Chargement des locataires…",
  "topbar.tenant.none": "Aucun locataire",
  "topbar.signOut": "Se déconnecter",
  "topbar.language": "Langue",
};

export const MESSAGES: Record<Locale, Catalog> = {
  en,
  "zh-Hans": zhHans,
  "zh-Hant": zhHant,
  ms,
  id,
  th,
  vi,
  ja,
  ko,
  ar,
  de,
  fr,
};

export function messagesFor(locale: Locale): Record<string, string> {
  return MESSAGES[locale] ?? MESSAGES.en;
}
