import { useLocation } from "react-router-dom";
export type NativeLoginKind = "wecom" | "dingtalk" | "feishu";
export function nativeLoginKind(value: string | null | undefined): value is NativeLoginKind {
  return value === "wecom" || value === "dingtalk" || value === "feishu";
}
export type IdentityKind = "ldap" | "oidc" | "cas" | "saml" | NativeLoginKind;

export type NamedLoginSource = {
  id: string;
  kind: IdentityKind;
  name: string;
  start_url: string;
};
export const validIdentitySource = (id: string | null | undefined): id is string =>
  typeof id === "string" && /^idp-[a-f0-9]{32}$/.test(id);
export function identitySourcePrefix(id: string | null | undefined) {
  return validIdentitySource(id) ? `/api/v1/identity-sources/${id}` : "";
}
export function useIdentitySource() {
  const { search } = useLocation();
  const id = new URLSearchParams(search).get("source_id");
  return { id: validIdentitySource(id) ? id : "", prefix: identitySourcePrefix(id) };
}
