export type DiscoveryPlan = {
  id: string;
  owner_id: string;
  owner: string;
  name: string;
  asset_ids: string[];
  collection_account: string;
  enabled: boolean;
  interval_seconds: number;
  config_revision: number;
  next_run?: string;
  last_run_id?: string;
  error_code?: string;
  last_run?: { state: string; items: { state: string; job_id?: string; review_id?: string }[] };
};
export type DiscoveryReceipt = {
  index: number;
  source: { asset_id: string; asset_name: string; account: string };
  collector: { id: string; name?: string };
  observed_at: string;
  receipt: {
    plan_id: string;
    sequence: number;
    run_id: string;
    job_id?: string;
    state: string;
    run: { items: { state: string; error_code?: string; review_id?: string }[] };
    job?: { state: string; error_code?: string; stdout?: string };
  };
};
export type DiscoveryReceiptPage = { results: DiscoveryReceipt[]; next_before: number };
