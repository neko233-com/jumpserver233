export type Request = (url: string, init?: RequestInit) => Promise<Response>;
export type Playbook = {
  id: string;
  owner_id: string;
  owner: string;
  name: string;
  description: string;
  visibility: string;
  revision: number;
  program_id: string;
  task_count: number;
  updated_at: string;
};
export type PlaybookDetail = Playbook & { files: Record<string, string> };
export type PlaybookStep = {
  id: string;
  task_index: number;
  name: string;
  module: string;
  iteration: number;
  attempt: number;
  state: string;
  final: boolean;
  changed: boolean;
  failed?: boolean;
  ignored?: boolean;
  job_id?: string;
  review_id?: string;
  error_code?: string;
  command_sha256?: string;
  created_at: string;
  finished_at?: string;
  retry_at?: string;
};
export type WorkflowItem = {
  asset_id: string;
  state: string;
  job_id?: string;
  review_id?: string;
  error_code?: string;
  task_cursor?: number;
  steps?: PlaybookStep[];
};
export type WorkflowRun = {
  archived?: boolean;
  id: string;
  owner_id: string;
  program_id?: string;
  playbook_id?: string;
  playbook_revision?: number;
  deadline?: string;
  trigger?: string;
  triggered_by?: { id: string; name: string };
  error_code?: string;
  items: WorkflowItem[];
};
export type Issue = {
  code?: string;
  file?: string;
  line?: number;
  column?: number;
  field?: string;
};
export const workspaceURL = (id: string) => "/api/v1/ops/playbooks/" + encodeURIComponent(id);
export function jsonBindings(value: string): Record<string, unknown> {
  const out: unknown = JSON.parse(value);
  if (!out || typeof out !== "object" || Array.isArray(out)) throw Error("invalid variables");
  return out as Record<string, unknown>;
}
