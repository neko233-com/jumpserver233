# SSH File Manager

> [中文](./SFTP.md) | English

Global SFTP, login-review bypass, and all-transfer audit use `assets.sftp_all`, `login_review.bypass`, and `audit.files.view_all` independently. See [RBAC.en.md](./RBAC.en.md).

## Current capabilities

- The SSH inventory shows **Files** to users with the `sftp` action. Administrators have it by default. Operators need an active grant matching the asset and configured SSH account. `sftp` implies inventory `view`, but does not grant terminal access.
- The browser file manager supports directory listing and navigation, folder creation, file upload/download, and deletion. The remote SFTP server rejects deletion of non-empty directories.
- The server reuses the encrypted SSH password and pinned SHA256 host-key fingerprint stored with the asset. Credentials are never returned to the browser.
- Paths are relative to the remote SFTP starting directory. Absolute paths, `..` traversal, and backslashes are rejected; symbolic links are not followed. Each upload or download is limited to 1 GiB.
- Uploads first go to a random temporary file in the same directory, then rename into place. Existing targets return a conflict by default. After confirmation, the server prefers the OpenSSH POSIX rename extension. Overwrite fails and preserves the original if the server does not support atomic replacement.

## API and audit

- `GET /api/v1/assets/{assetID}/files?path=relative/path` lists a directory.
- `POST /api/v1/assets/{assetID}/directories` with JSON `{ "path": "relative/folder" }` creates a directory.
- `PUT /api/v1/assets/{assetID}/files/content?path=relative/file` uploads the raw request body; `overwrite=true` allows replacing an existing regular file.
- `GET /api/v1/assets/{assetID}/files/content?path=relative/file` downloads a file. `DELETE` on the same route removes a regular file, a symbolic link itself, or an empty directory.
- Each upload, download, folder creation, and deletion records the operator, asset, action, relative path, byte count, result code, and timestamp. File contents and SSH credentials are excluded. The index is `JMS_DATA_DIR/file-transfers/index.jsonl`. `GET /api/v1/file-transfers` returns all records to administrators and only the caller's records to operators.
- In cluster mode, active and candidate nodes need a shared read/write `file-transfers` directory.

## Current limits

SFTP path checks do not replace the remote Linux account's own filesystem permissions; administrators should still use a least-privilege SSH account. The per-file limit is fixed and has no administrator setting yet.
