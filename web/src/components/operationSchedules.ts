export type Schedule = {
  kind: string;
  run_at?: string;
  interval_seconds?: number;
  cron_expression?: string;
  timezone?: string;
  end_at?: string;
  misfire_policy?: string;
  grace_seconds?: number;
  fold_policy?: string;
};
export type ScheduledPlan = Schedule & {
  id: string;
  name: string;
  owner_id: string;
  config_revision: number;
  enabled: boolean;
  last_run_id?: string;
  last_scheduled_at?: string;
  next_run?: string;
  skipped_triggers?: number;
};
export type ScheduleDraft = {
  kind: string;
  runAt: string;
  interval: number;
  expression: string;
  timezone: string;
  endAt: string;
  misfire: string;
  grace: number;
  fold: string;
};
const localInput = (value?: string) => {
  if (!value) return "";
  const d = new Date(value);
  if (!Number.isFinite(d.getTime())) return "";
  return new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 19);
};
export const scheduleDraft = (p?: Schedule): ScheduleDraft => ({
  kind: p?.kind || "batch",
  runAt: localInput(p?.run_at),
  interval: p?.interval_seconds || 3600,
  expression: p?.cron_expression || "0 2 * * *",
  timezone: p?.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
  endAt: localInput(p?.end_at),
  misfire: p?.misfire_policy || "coalesce",
  grace: p?.grace_seconds || 60,
  fold: p?.fold_policy || "once",
});
export function schedulePayload(d: ScheduleDraft): Schedule {
  return {
    kind: d.kind,
    ...(d.kind !== "batch" && d.runAt ? { run_at: new Date(d.runAt).toISOString() } : {}),
    ...(d.kind === "interval" ? { interval_seconds: d.interval } : {}),
    ...(["cron", "interval"].includes(d.kind) && d.endAt
      ? { end_at: new Date(d.endAt).toISOString() }
      : {}),
    ...(d.kind === "cron"
      ? {
          cron_expression: d.expression,
          timezone: d.timezone,
          misfire_policy: d.misfire,
          grace_seconds: d.grace,
          fold_policy: d.fold,
        }
      : {}),
  };
}
