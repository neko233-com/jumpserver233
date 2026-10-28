export default { sshConfigImport: {
  title: "Import local SSH config",
  hint: "Sync SSH accounts you can connect to in the current organization as local aliases. Connections still use bastion grants, review and audit; target credentials are not exported.",
  host: "Bastion SSH address", port: "SSH port",
  chooseFile: "Select your local ~/.ssh/config and grant file access to update its dedicated block. Other settings are preserved. Verify the bastion host key on first connection.",
  fallback: "This browser or HTTP address cannot edit local files. Install the jms client, configure JMS_SERVER_URL and platform authentication, then run the following command; add --preview to inspect it first.",
  windows: "Windows PowerShell", unix: "macOS / Linux shell",
  failed: "Import did not complete. Select the correct config file and check permissions, conflicts, or concurrent edits before retrying.",
  success: "Synced {{count}} accounts. Connect using the generated jms aliases.", close: "Close", import: "Choose config and import",
} };
