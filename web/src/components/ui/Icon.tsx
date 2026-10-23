import type { SVGProps } from "react";

const paths = {
  terminal: "m5 7 4 5-4 5m7 0h7M3 3h18v18H3z",
  server: "M4 3h16v7H4zM4 14h16v7H4zM7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6",
  activity: "M3 12h4l3-8 4 16 3-8h4",
  key: "M15 7a4 4 0 1 0-7 2.6L3 15v4h4v-3h3l3-3M15 7h.01",
  shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6zM9 12l2 2 4-4",
  history: "M3 11a9 9 0 1 1 2 7M3 4v7h7M12 7v5l3 2",
  users:
    "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M20 21v-2a4 4 0 0 0-3-3.9M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8M17 3a4 4 0 0 1 0 8",
  settings:
    "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8M9 3h6l1 3 3 1 2 5-2 5-3 1-1 3H9l-1-3-3-1-2-5 2-5 3-1z",
  search: "M10.5 3a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15M16 16l5 5",
  chevron: "m9 5 7 7-7 7",
  plus: "M12 5v14M5 12h14",
  refresh: "M20 7v5h-5M4 17v-5h5M5.6 7a7 7 0 0 1 11.6-2L20 8M4 16l2.8 3A7 7 0 0 0 18.4 17",
  close: "m6 6 12 12M6 18 18 6",
  folder: "M3 7V4h6l2 3h10v13H3z",
  file: "M14 3H5v18h14V8zM14 3v6h5M8 13h8M8 17h5",
  expand: "M8 3H3v5M16 3h5v5M3 16v5h5M21 16v5h-5",
  collapse: "M3 8h5V3M21 8h-5V3M8 21v-5H3M16 21v-5h5",
  globe: "M3 12h18M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M12 3c-5 5-5 13 0 18 5-5 5-13 0-18",
  layers: "m3 7 9-4 9 4-9 4zM3 12l9 4 9-4M3 17l9 4 9-4",
  list: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  logout: "M9 3H3v18h6M14 7l5 5-5 5M7 12h13",
  check: "m5 12 4 4L19 6",
  arrow: "M5 12h14m-6-6 6 6-6 6",
  download: "M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5",
  filter: "M3 5h18l-7 8v6l-4 2v-8z",
  sun: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1 1M18 18l1 1M5 19l1-1M18 6l1-1",
} as const;
export type IconName = keyof typeof paths;

export default function Icon({
  name,
  size = 18,
  ...props
}: SVGProps<SVGSVGElement> & { name: IconName; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      <path d={paths[name]} />
    </svg>
  );
}
