import OIDCLogin, { type LoginCompletionProps } from "./OIDCLogin";
import "../i18n/locales/features/enterprise-login/register";
export default function EnterpriseLogin(props: LoginCompletionProps) {
  return <OIDCLogin {...props} namespace="enterpriseLogin" />;
}
