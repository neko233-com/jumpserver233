export type PasswordRotation = {
  shared?: boolean;
  state: "scheduled" | "due" | "rotating" | "failed" | "recovery_required" | "disabled";
  last_rotated_at: string;
  next_rotation_at: string;
  error_code?: string;
};
export type SSHKeyRotation = {
  shared?: boolean;
  state: string;
  enabled: boolean;
  pending: boolean;
  can_cancel: boolean;
  request_id?: string;
  operation_id?: string;
  expected_revision?: number;
  next_rotation_at?: string;
  error_code?: string;
};
export type AccountChoice = {
  id: string;
  name: string;
  username: string;
  active: boolean;
  default: boolean;
  credential_type: "password" | "ssh_key";
  credential_revision: number;
  key_fingerprint?: string;
  permissions: string[];
  password_rotation?: PasswordRotation;
  ssh_key_rotation?: SSHKeyRotation;
};

export type ManagedAccount = AccountChoice & {
  asset_id: string;
  remark: string;
  discovery_id?: string;
  version: string;
  password_rotation_enabled: boolean;
  key_rotation_enabled: boolean;
};
