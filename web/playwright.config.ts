import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "@playwright/test";

const webDir = fileURLToPath(new URL(".", import.meta.url));
const serverDir = resolve(webDir, "../server");
const testDataDir = process.env.JMS_E2E_DATA_DIR;
const frontend =
  process.env.JMS_E2E_PRODUCTION === "true"
    ? "pnpm exec vite preview --config e2e/preview.vite.config.ts"
    : "pnpm exec vite";
if (!testDataDir)
  throw new Error(
    "Run browser tests with `pnpm test:e2e` so temporary test data is cleaned safely",
  );

const config = defineConfig({
  testDir: "./e2e",
  // Archived Enterprise UI cases remain as source references. The shipped mini
  // graph has no routes for these pages, and needs no corresponding fixtures.
  testIgnore: [
    "**/{announcements,asset-discovery,assistant,branding,clickhouse,database,desktop-monitor,enterprise-login,identity-sources,kubernetes,mysql,native-notifications,nosql,organization-overview,pam,radius,rdp,replay-storage,session-security,sms-mfa,sqlserver,telnet}.spec.ts",
  ],
  grepInvert: /signs in over real LDAPS|signs in through a real synthetic OIDC|completes CAS service-ticket|completes SAML signed-assertion/,
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["./e2e/report.mjs"]],
  timeout: 30_000,
  expect: { timeout: 7_500 },
  use: {
    actionTimeout: 10_000,
    baseURL: "http://127.0.0.1:5177",
    browserName: "chromium",
    trace: "off",
    screenshot: "only-on-failure",
  },
  webServer: [
    {
      command: "node ./testsupport/radius/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:18514/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_RADIUS_UDP_PORT: "18512",
        JMS_QA_RADIUS_TLS_PORT: "18513",
        JMS_QA_RADIUS_HEALTH_PORT: "18514",
        JMS_QA_RADIUS_NETWORK: "",
      },
    },
    {
      command: "go run ./testsupport/notificationfixture/cmd",
      cwd: serverDir,
      url: "http://127.0.0.1:12604/health",
      timeout: 120_000,
      reuseExistingServer: false,
    },
    {
      command: "node ./testsupport/systemdvm/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:12326/health",
      timeout: 900_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_SYSTEMD_SSH_PORT: "12325",
        JMS_QA_SYSTEMD_HEALTH_PORT: "12326",
        JMS_QA_SYSTEMD_NETWORK: "",
      },
    },
    {
      command: "go run ./cmd/server",
      cwd: serverDir,
      url: "http://127.0.0.1:8085/api/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: {
        JMS_ADDR: "127.0.0.1:8085",
        JMS_DATA_DIR: resolve(testDataDir, "default-admin"),
        JMS_PUBLIC_URL: "http://127.0.0.1:15180",
        JMS_DEFAULT_ADMIN_ENABLED: "true",
        JMS_CLUSTER_MODE: "false",
        JMS_ADMIN_TOKEN: "",
        JMS_TRUSTED_PROXIES: "",
        JMS_MONITOR_INTERVAL: "1h",
      },
    },
    {
      command: frontend + " --host 127.0.0.1 --port 15180 --strictPort",
      cwd: webDir,
      url: "http://127.0.0.1:15180/api/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: { VITE_API_TARGET: "http://127.0.0.1:8085" },
    },
    {
      command: "node ./testsupport/rdp/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:19392/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: { JMS_QA_RDP_PORT: "19391", JMS_QA_RDP_HEALTH_PORT: "19392", JMS_QA_RDP_NETWORK: "" },
    },
    {
      command: "node ./testsupport/telnet/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:16526/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_TELNET_PORT: "16525",
        JMS_QA_TELNET_TLS_PORT: "16994",
        JMS_QA_TELNET_HEALTH_PORT: "16526",
        JMS_QA_TELNET_NETWORK: "",
      },
    },
    {
      command: "node ./testsupport/kubernetes/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:16446/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_KUBERNETES_PORT: "16445",
        JMS_QA_KUBERNETES_HEALTH_PORT: "16446",
        JMS_QA_KUBERNETES_NETWORK: "",
      },
    },
    {
      command: "node ./testsupport/nosql/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:15494/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_NOSQL_ENGINE: "redis",
        JMS_QA_REDIS_PORT: "15493",
        JMS_QA_REDIS_HEALTH_PORT: "15494",
        JMS_QA_REDIS_NETWORK: "",
      },
    },
    {
      command: "node ./testsupport/nosql/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:15504/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_NOSQL_ENGINE: "mongodb",
        JMS_QA_MONGODB_PORT: "15503",
        JMS_QA_MONGODB_HEALTH_PORT: "15504",
        JMS_QA_MONGODB_NETWORK: "",
      },
    },
    {
      command: "node ./testsupport/clickhouse/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:15484/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_CLICKHOUSE_PORT: "15483",
        JMS_QA_CLICKHOUSE_HEALTH_PORT: "15484",
        JMS_QA_CLICKHOUSE_NETWORK: "",
      },
    },
    {
      command: "node ./testsupport/sqlserver/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:15474/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_SQLSERVER_PORT: "15473",
        JMS_QA_SQLSERVER_HEALTH_PORT: "15474",
        JMS_QA_SQLSERVER_NETWORK: "",
      },
    },
    {
      command: "node ./testsupport/mysql/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:15466/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_SQL_ENGINE: "mysql",
        JMS_QA_MYSQL_PORT: "15465",
        JMS_QA_MYSQL_HEALTH_PORT: "15466",
        JMS_QA_MYSQL_NETWORK: "",
      },
    },
    {
      command: "node ./testsupport/mysql/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:15468/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_SQL_ENGINE: "mariadb",
        JMS_QA_MYSQL_PORT: "15467",
        JMS_QA_MYSQL_HEALTH_PORT: "15468",
        JMS_QA_MYSQL_NETWORK: "",
      },
    },
    {
      command: "node ./testsupport/postgres/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:15443/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_POSTGRES_PORT: "15444",
        JMS_QA_POSTGRES_HEALTH_PORT: "15443",
        JMS_QA_POSTGRES_NETWORK: "",
      },
    },
    {
      command: "node ./testsupport/openssh/run.mjs",
      cwd: serverDir,
      url: "http://127.0.0.1:12242/health",
      timeout: 300_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_KEYHOST_SSH_PORT: "12241",
        JMS_QA_KEYHOST_HTTP_PORT: "12242",
        JMS_QA_KEYHOST_PROTECTION: "true",
        JMS_QA_KEYHOST_NETWORK: "",
      },
    },
    {
      command: "go run ./testsupport/sshgateway/cmd",
      cwd: serverDir,
      url: "http://127.0.0.1:12238/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_GATEWAY_ADDR: "127.0.0.1:12237",
        JMS_QA_GATEWAY_HTTP_ADDR: "127.0.0.1:12238",
        JMS_QA_GATEWAY_TARGET: "127.0.0.1:12222",
      },
    },
    {
      command: "go run ./cmd/server",
      cwd: serverDir,
      url: "http://127.0.0.1:18185/api/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: {
        JMS_ADDR: "127.0.0.1:18185",
        JMS_TRUSTED_PROXIES: "",
        JMS_DATA_DIR: resolve(testDataDir, "passkey"),
        JMS_ADMIN_TOKEN: "",
        JMS_CLUSTER_MODE: "false",
        JMS_DEFAULT_ADMIN_ENABLED: "false",
        JMS_MONITOR_INTERVAL: "1h",
        JMS_PUBLIC_URL: "http://localhost:15178",
      },
    },
    {
      command: "pnpm exec vite --host 127.0.0.1 --port 15178 --strictPort",
      cwd: webDir,
      url: "http://localhost:15178/api/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: { VITE_API_TARGET: "http://127.0.0.1:18185" },
    },

    {
      command: "go run ./testsupport/samlprovider/cmd",
      cwd: serverDir,
      url: "http://127.0.0.2:12235/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: { JMS_QA_SAML_ADDR: "127.0.0.2:12235" },
    },
    {
      command: "go run ./testsupport/casprovider/cmd",
      cwd: serverDir,
      url: "http://127.0.0.1:12233/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: { JMS_QA_CAS_ADDR: "127.0.0.1:12233" },
    },
    {
      command: "go run ./testsupport/ldapserver/cmd",
      cwd: serverDir,
      url: "http://127.0.0.1:12230/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: { JMS_QA_LDAP_ADDR: "127.0.0.1:12229", JMS_QA_LDAP_HEALTH_ADDR: "127.0.0.1:12230" },
    },
    {
      command: "go run ./testsupport/oidcprovider/cmd",
      cwd: serverDir,
      url: "http://127.0.0.1:12226/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: { JMS_QA_OIDC_ADDR: "127.0.0.1:12226" },
    },
    {
      command: "go run ./testsupport/sshmonitor",
      cwd: serverDir,
      url: "http://127.0.0.1:12223/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: {
        JMS_QA_SSH_ADDR: "127.0.0.1:12222",
        JMS_QA_HTTP_ADDR: "127.0.0.1:12223",
      },
    },
    {
      command: "go run ./cmd/server",
      cwd: serverDir,
      url: "http://127.0.0.1:8083/api/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: {
        JMS_ADDR: "127.0.0.1:8083",
        JMS_TRUSTED_PROXIES: "",
        JMS_DATA_DIR: testDataDir,
        JMS_ADMIN_TOKEN: "",
        JMS_CLUSTER_MODE: "false",
        JMS_DEFAULT_ADMIN_ENABLED: "false",
        JMS_MONITOR_INTERVAL: "1h",
        JMS_PUBLIC_URL: "http://127.0.0.1:5177",
        NO_PROXY: "localhost,127.0.0.0/8,::1",
      },
    },
    {
      command: frontend + " --host 127.0.0.1 --port 5177 --strictPort",
      cwd: webDir,
      url: "http://127.0.0.1:5177/api/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: { VITE_API_TARGET: "http://127.0.0.1:8083" },
    },
  ],
});

// Keep only SSH, native-host, authentication and notification fixtures. In
// particular no cloud, SQL, Kubernetes, RDP or external IdP service is started.
const miniPorts = new Set(["12326", "12604", "8085", "15180", "12242", "12238", "18185", "15178", "12223", "8083", "5177"]);
if (Array.isArray(config.webServer)) {
  config.webServer = config.webServer.filter((server) => miniPorts.has(new URL(server.url!).port));
}
export default config;
