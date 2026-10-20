# Approved Technical Contract
## Zero Trust Secure File Sharing System with Role-Based Access Control and File Integrity Verification

**Status:** Approved implementation baseline  
**Cost target:** ₹0 additional software/service cost  
**Runtime:** Python 3.12, local machine  
**Scope:** Local demonstration and course project; no production/high-volume claim

This document freezes the shared architecture and interfaces. Implementations must follow it. If a change is necessary, propose it to the team and update this contract before changing dependent modules.

## 1. Non-negotiable cost and deployment requirements

- The project must be developed, run, tested, demonstrated, and documented without purchasing software, certificates, hosting, APIs, subscriptions, or developer tools.
- Use free/open-source packages and Python standard-library features wherever practical.
- Run locally using SQLite and local disk storage. No cloud runtime or permanent internet connection is required after dependencies are installed.
- Existing computer, operating system, internet plan for initial package download (if needed), and electricity are assumed available; these are not project software/service purchases.
- Direct third-party runtime dependencies: `bcrypt`, `cryptography`, and `streamlit`. Pin tested versions and the complete resolved dependency set in `requirements.txt` after implementation; verify a clean virtual-environment install.
- Use Python `unittest`; no paid testing service is required.
- No AI API, public certificate authority, paid TLS certificate, public domain, commercial database, cloud key-management service, cloud storage, or OpenSSL installation is required.
- Streamlit runs as a local process and is opened in an existing browser; Streamlit-hosted services are not part of the design.

## 2. Team ownership and import boundaries

### Member 1 — Networking and transport
Owns `client/` and `server/`: TCP framing, TLS, local development-certificate tooling, transfer handling, server orchestration, storage files, and first-admin bootstrap.

### Member 2 — Security
Owns `security/`: password hashing, session tokens, authorization policy, AES-GCM encryption/decryption, SHA-256 integrity, and encryption-key file operations.

### Member 3 — Application and database
Owns `database/` and `ui/`: SQLite schema/functions, audit persistence, Streamlit UI, and shared contract/setup documentation.

Import boundaries:
- The UI calls only `client.api`; it never accesses SQLite, server storage, decryption, or authorization directly.
- The client communicates with the server over TLS.
- The server authenticates and authorizes every protected operation, then calls security/database/storage functions.
- Database modules do not import client, server, security, or UI modules.
- Security modules do not import database or application modules.
- Client modules do not import server modules.
- No circular imports. Server handlers translate security/database/server exceptions into stable wire errors.

## 3. Repository and branch policy

The approved base commit on `main` at contract approval was:
`9297fd74c215b7b5add18a70ab79f8e12f112b99`.

Branches are created from that commit:
- `networking`: Member 1's `client/` and `server/`
- `security`: Member 2's `security/`
- `application`: Member 3's `database/`, `ui/`, and shared documentation

Keep `main` as the integration branch. Do not implement directly on `main`. Review changes and test before merging via pull requests. Avoid editing another member's owned modules without coordinating first. This document is initially added to `application`; other branches should refer to the same contract.

## 4. Security model and policy

### Mutual TLS and application login are distinct

1. Mutual TLS authenticates a connecting computer/device certificate. The server requires a client certificate signed by the locally generated CA. The client validates the server certificate against that CA and verifies the configured hostname.
2. Application login identifies an individual account. After TLS succeeds, the client sends username/password in the `login` operation. The server checks the bcrypt hash and returns a session token only for an active account.
3. For every protected request, the server hashes the presented session token, loads its session and user account, checks expiration/revocation/active status, obtains the role from the database, and calls `security.authorization.authorize`.

A valid client certificate does not create, identify, or grant an application account or role. Never derive a user ID or role from a certificate subject/CN or client-supplied role field.

### Roles

**Admin**
- List, download, delete, grant/revoke access to any file.
- Create users, change roles, activate/deactivate users.

**User**
- Upload files.
- List files they own or have been granted.
- Download owned or granted files.
- Delete only files they own.
- Grant/revoke access only for files they own.

Ownership remains with the uploader. A grant does not transfer ownership. Revocation prevents subsequent access. Admin accounts cannot delete user accounts; accounts are deactivated to preserve ownership and audit history. Inactive users cannot log in or access files; their grants remain but cannot be used while they are inactive.

The server—not the UI—enforces permissions on every protected request. For a missing or unauthorized file, return `NOT_FOUND` to avoid disclosing file existence.

## 5. Authentication and cryptography

- Passwords: 12–72 UTF-8 bytes. Hash with bcrypt, fresh salt, cost 12. Validate the bcrypt byte limit before hashing.
- Session token: 32 cryptographically random bytes, URL-safe Base64 without padding (43 characters). Store only the SHA-256 digest of the token. Session lifetime is 8 hours, not sliding; sessions can be revoked.
- File encryption: AES-256-GCM, fresh 12-byte nonce per encryption. Associated data: `b"ZTSF:v1:" + storage_id.encode("ascii")`.
- Stored ciphertext format: `b"ZTSF\x01" + nonce + ciphertext-and-tag`. Authentication/decryption failures raise `EncryptionError`.
- Integrity: compute SHA-256 on plaintext during upload and verify after decryption. Client also verifies downloaded byte count and SHA-256 before finalizing the destination.
- Key file: exactly 32 random bytes, generated once, refuses to overwrite existing key, stored outside Git in a user-owned application data directory. Server refuses to start if key is missing/invalid. Back it up securely; losing it makes stored files unrecoverable. Key rotation is out of scope.
- Never log passwords, tokens, private keys, file contents, or secrets. Do not return stack traces, SQL statements, or private paths to clients.

## 6. Local TLS certificates and configuration

Use mutual TLS with TLS 1.2 or later:
- The server requires a client certificate (`CERT_REQUIRED`) and trusts only the configured local CA.
- The client requires a server certificate issued by that CA and performs hostname verification. Pass `server_hostname=ZTS_HOST` when wrapping the socket.
- Default host is `localhost`; server certificate SANs include `localhost` and loopback IPs. For a different LAN hostname/IP, issue a certificate containing that exact SAN and configure the same host.
- Generate CA, server, and per-computer client keys/certificates locally with `cryptography`; do not install them in the OS trust store. TLS contexts load the CA explicitly.
- Store CA/server/client private keys and certificates outside the repository. Retain the CA private key securely for issuing client certificates. Certificate-generation functions refuse to overwrite existing outputs.
- Certificate revocation for this demo is handled by replacing the CA and reissuing certificates; there is no CRL service.

Required environment variables:
`ZTS_HOST`, `ZTS_PORT`, `ZTS_DB_FILE`, `ZTS_STORAGE_DIR`, `ZTS_CA_CERT_FILE`, `ZTS_TLS_CERT_FILE`, `ZTS_TLS_KEY_FILE`, `ZTS_CLIENT_CERT_FILE`, `ZTS_CLIENT_KEY_FILE`, `ZTS_KEY_FILE`.

Paths point to local files/directories outside the repository. Use `%LOCALAPPDATA%` on Windows or the user's local data directory on Linux/macOS. Document OS-native permissions for private files.

## 7. TCP protocol

One TLS connection carries exactly one operation. The client transport opens the connection; the server app accepts, wraps, and closes it. No idle keep-alive.

- Control frame: 4-byte unsigned big-endian byte length, then UTF-8 JSON; maximum 1 MiB.
- Binary frame: 8-byte unsigned big-endian byte length, then exactly that many raw bytes; no Base64.
- Maximum plaintext file size: 50 MiB (52,428,800 bytes).
- Maximum active accepted connections: four, including TLS handshakes.
- Both peers loop until all requested bytes are sent/received. EOF before completion is a disconnect/truncation. Reject oversized frames and close.
- Use exact-read and send-all loops. Validate binary length header against expected size and 50 MiB cap before reading body.

Request envelope:
```json
{"version":1,"request_id":"UUIDv4","action":"login","payload":{}}
```

Success response:
```json
{"version":1,"request_id":"same UUID","ok":true,"data":{}}
```

Error response:
```json
{"version":1,"request_id":"same UUID or null if undecodable","ok":false,"error":{"code":"FORBIDDEN","message":"Access denied"}}
```

Every reply echoes the request ID when it can be decoded. Error messages are safe and generic. Stable error codes:
`INVALID_REQUEST`, `UNSUPPORTED_VERSION`, `MALFORMED_JSON`, `FRAME_TOO_LARGE`, `INVALID_CREDENTIALS`, `AUTH_REQUIRED`, `SESSION_EXPIRED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `INVALID_FILENAME`, `FILE_TOO_LARGE`, `SIZE_MISMATCH`, `TRANSFER_INCOMPLETE`, `INTEGRITY_FAILURE`, `STORAGE_ERROR`, `DATABASE_ERROR`, `TLS_ERROR`, `INTERNAL_ERROR`.

For undecodable control frames, server app makes a best-effort error response with null request ID, then closes. Valid JSON with invalid fields/action gets a normal error envelope with the original request ID. Never send two responses for one failure.

### Connection limits and timeouts

- Acquire a connection slot before starting TLS; acquisition is atomic and non-blocking. If all four slots are occupied, immediately close the newly accepted raw socket without starting TLS or sending application data.
- Each slot is released exactly once in a `finally` block covering TLS handshake, control frames, handler/transfer, and socket closure. If worker startup fails, close the socket and release the slot.
- TLS handshake timeout: 5 seconds.
- Control-frame read/write timeout: 10 seconds per complete control frame.
- Binary transfer timeout: 30 seconds without progress; reset only when bytes are successfully received/sent. This is an inactivity timeout, not a total transfer deadline.
- Apply handshake timeout before TLS wrapping and the relevant timeout during protocol reads/writes. A stalled operation must not occupy a slot indefinitely.
- Upload timeout/incomplete transfer discards transfer data and temporary storage, creates no visible file metadata and no success audit. Download timeout closes the connection; client removes its incomplete temporary file.
- Record a failure audit when an authenticated actor is known and the database remains available.
- Test simultaneous arrivals, stalled handshakes, control/body stalls, all slot-release paths, and successful subsequent connection after slot release.

## 8. Actions and payloads

All protected actions except `login` require `payload.token`.

| Action | Required payload | Success data / sequence |
|---|---|---|
| `login` | `username`, `password` | `token`, `expires_at`, `user: {user_id, username, role}` |
| `logout` | `token` | `{}` |
| `list_files` | `token` | `files: [{file_id, filename, owner_username, size_bytes, sha256_hex, created_at, access}]` |
| `upload` | `token`, `filename`, `size_bytes`, `share_with` | Ready response, binary frame, then `file_id`, `sha256_hex` |
| `download` | `token`, `file_id` | Metadata response, then plaintext binary frame |
| `delete` | `token`, `file_id` | `{}` |
| `share.grant` | `token`, `file_id`, `username` | `{}` |
| `share.revoke` | `token`, `file_id`, `username` | `{}` |
| `admin.create_user` | `token`, `username`, `password`, `role` | `user_id` |
| `admin.set_user_role` | `token`, `user_id`, `role` | `{}` |
| `admin.set_user_active` | `token`, `user_id`, `is_active` | `{}` |

Upload rules:
1. Validate session, permission, filename, size, and recipients before sending ready.
2. Ready response is `{"ready": true}`.
3. Receive one binary frame whose length exactly equals `size_bytes`.
4. Compute plaintext SHA-256; encrypt and store ciphertext.
5. In one DB transaction, commit file metadata, grants, and success audit.
6. Send final success response with file ID and digest.
7. If transfer/persistence fails after ready, send one final error if the socket remains writable, clean temporary/final ciphertext as appropriate, and close. Incomplete upload creates no visible file metadata or success audit.
8. `share_with` supports at most 100 distinct usernames; nonexistent/inactive recipients cause upload to fail.

Download rules:
1. Validate session and permission.
2. Read ciphertext, decrypt, and verify SHA-256 before sending success metadata.
3. Send metadata `filename`, `size_bytes`, `sha256_hex`.
4. Send one length-prefixed plaintext binary frame.
5. If connection drops during transfer, client discards the incomplete temporary file. Once metadata is sent, do not try to replace it with a second control error; client detects truncation.

## 9. Filenames, storage, and file lifecycle

- Filename is Unicode NFC, 1–255 UTF-8 bytes; reject `/`, backslash, NUL, control characters, `.`, and `..`.
- Never use the user-provided filename as a storage path. Storage uses only server-generated lowercase 32-character UUID hex identifiers.
- Maximum file size is 50 MiB. Whole-file buffers are acceptable at this cap; high-volume use is out of scope.
- Upload ciphertext is written to a temporary file in the storage directory, flushed, and atomically renamed before the database transaction inserts metadata/grants/audit. If the transaction fails, remove ciphertext.
- A crash between storage rename and DB commit can leave an orphan. On startup, compare storage IDs with DB references and remove unreferenced objects older than one hour.
- Download client writes to a temporary file in the destination directory, checks byte count and SHA-256, then atomically renames it to the destination. On failure, remove the temporary file and leave the existing destination unchanged.
- Delete: commit metadata/ACL deletion and success audit together; then remove ciphertext. A removal failure is logged for cleanup retry. Audit records remain with null file ID.
- All temporary-file and orphan cleanup paths must be tested.

## 10. Module files and exact public interfaces

### Member 1: client and server

Files:
```text
client/__init__.py
client/api.py
client/transport.py
client/errors.py
server/__init__.py
server/app.py
server/protocol.py
server/handlers.py
server/storage.py
server/tls.py
server/dev_certs.py
server/bootstrap.py
server/errors.py
```

Client API:
```python
login(username: str, password: str) -> dict
logout(token: str) -> None
list_files(token: str) -> list[dict]
upload_file(token: str, source: Path, share_with: list[str] | None = None) -> dict
download_file(token: str, file_id: int, destination: Path) -> dict
delete_file(token: str, file_id: int) -> None
grant_file_access(token: str, file_id: int, username: str) -> None
revoke_file_access(token: str, file_id: int, username: str) -> None
admin_create_user(token: str, username: str, password: str, role: str) -> int
admin_set_user_role(token: str, user_id: int, role: str) -> None
admin_set_user_active(token: str, user_id: int, is_active: bool) -> None
```

Client transport:
```python
request_control(request: dict) -> dict
upload_binary(request: dict, source: BinaryIO, size_bytes: int) -> dict
download_binary(request: dict, destination: Path) -> dict
```
Each transport function opens exactly one TLS connection, sends one initial control frame, reads the response sequence for the action, and closes in `finally`.
- `request_control`: one control request and one control response; for actions without binary transfer.
- `upload_binary`: send upload control, read ready response, send one binary frame, read final response; return final data or raise `ClientError`.
- `download_binary`: send download control, read metadata, read one binary frame to a temp file beside destination, verify count and digest, atomically rename, return metadata.
- `client.api` builds requests and calls exactly one transport function per operation. It does not open sockets.

Server app:
```python
serve_forever(host: str, port: int, tls_context: ssl.SSLContext) -> None
handle_connection(raw_sock: socket.socket, peer: tuple[str, int], tls_context: ssl.SSLContext) -> None
```
`server.app` accepts connections, enforces four slots/timeouts, wraps TLS, reads exactly one initial control frame, dispatches once, and closes the connection. It calls `server.protocol.recv_control()` once and passes the request and TLS socket to the handler. Release the slot exactly once on every path.

Server handler:
```python
handle_request(request: dict, peer: tuple[str, int], conn: ssl.SSLSocket) -> None
```
The handler validates request/session/permissions, orchestrates control response sequences and transfers, and calls database/security/storage modules. It does not accept sockets or wrap TLS.

Server protocol:
```python
recv_exact(sock: ssl.SSLSocket, size: int) -> bytes
send_all(sock: ssl.SSLSocket, data: bytes) -> None
recv_control(sock: ssl.SSLSocket) -> dict
send_control(sock: ssl.SSLSocket, message: dict) -> None
recv_binary(sock: ssl.SSLSocket, expected_size: int) -> bytes
send_binary(sock: ssl.SSLSocket, source: BinaryIO, size_bytes: int) -> None
```

Server storage:
```python
new_storage_id() -> str
write_encrypted(storage_id: str, ciphertext: bytes) -> None
read_encrypted(storage_id: str) -> bytes
remove_storage_object(storage_id: str) -> None
cleanup_orphans(referenced_storage_ids: set[str], older_than_epoch: int) -> int
```

TLS:
```python
create_server_context(cert_file: Path, key_file: Path, ca_file: Path) -> ssl.SSLContext
create_client_context(ca_file: Path, client_cert_file: Path, client_key_file: Path) -> ssl.SSLContext
```
The client transport uses `server_hostname=ZTS_HOST` so hostname validation occurs.

Development certificate tooling:
```python
generate_development_ca(ca_key_path: Path, ca_cert_path: Path) -> None
issue_server_certificate(ca_key_path: Path, ca_cert_path: Path, server_key_path: Path, server_cert_path: Path, hostname: str) -> None
issue_client_certificate(ca_key_path: Path, ca_cert_path: Path, client_key_path: Path, client_cert_path: Path, client_name: str) -> None
```
All generation functions refuse to overwrite existing outputs.

Bootstrap:
```python
create_first_admin(username: str, password: str) -> int
```
Prompt securely for the first Admin password in the terminal; only create the first account if no users exist. No hardcoded credentials.

Exceptions:
- `client.errors.ClientError(code: str, message: str)`
- `server.errors.ProtocolError(code: str, message: str, request_id: str | None = None)`
- `server.errors.StorageError(message: str)`
- `server.errors.RequestError(code: str, message: str)`
- Protocol errors cover framing/parsing/transfer errors. Storage errors map to `STORAGE_ERROR`; request errors carry a stable wire code.

### Member 2: security

Files:
```text
security/__init__.py
security/errors.py
security/passwords.py
security/sessions.py
security/authorization.py
security/encryption.py
security/integrity.py
security/key_store.py
```

`security.errors` defines `SecurityError(code: str, message: str)` and subclasses `PasswordError`, `SessionError`, `AuthorizationError`, `EncryptionError` with the same constructor signature.

Public interfaces:
```python
# security/passwords.py
hash_password(password: str) -> bytes
verify_password(password: str, password_hash: bytes) -> bool

# security/sessions.py
generate_token() -> str
token_digest(token: str) -> bytes
validate_session(token: str, session_record: dict | None, now_epoch: int) -> dict

# security/authorization.py
authorize(user: dict, action: str, file_record: dict | None = None) -> None

# security/encryption.py
load_encryption_key(path: Path) -> bytes
encrypt_file(plaintext: bytes, storage_id: str, key: bytes) -> bytes
decrypt_file(ciphertext: bytes, storage_id: str, key: bytes) -> bytes

# security/integrity.py
sha256_digest(data: bytes) -> bytes
sha256_hex(data: bytes) -> str
verify_sha256(data: bytes, expected_digest: bytes) -> bool

# security/key_store.py
create_encryption_key_file(path: Path) -> None
```
`validate_session` returns `{user_id, username, role}` or raises `SessionError`.

### Member 3: database and UI

Files:
```text
database/__init__.py
database/errors.py
database/core.py
database/users.py
database/sessions.py
database/files.py
database/audit.py
ui/__init__.py
ui/app.py
```

`database.errors.DatabaseError(message: str)` wraps SQLite failures without exposing SQL statements or database paths.

Public interfaces:
```python
# database/core.py
transaction() -> ContextManager[sqlite3.Connection]
initialize() -> None

# database/users.py
get_user_by_username(conn: sqlite3.Connection, username: str) -> dict | None
get_user_by_id(conn: sqlite3.Connection, user_id: int) -> dict | None
create_user(conn: sqlite3.Connection, username: str, password_hash: bytes, role: str, now_epoch: int) -> int
set_user_role(conn: sqlite3.Connection, user_id: int, role: str) -> None
set_user_active(conn: sqlite3.Connection, user_id: int, is_active: bool) -> None
list_users(conn: sqlite3.Connection) -> list[dict]

# database/sessions.py
create_session(conn: sqlite3.Connection, token_hash: bytes, user_id: int, created_at: int, expires_at: int) -> None
get_session(conn: sqlite3.Connection, token_hash: bytes) -> dict | None
revoke_session(conn: sqlite3.Connection, token_hash: bytes, revoked_at: int) -> None
revoke_user_sessions(conn: sqlite3.Connection, user_id: int, revoked_at: int) -> None
delete_expired_sessions(conn: sqlite3.Connection, now_epoch: int) -> int

# database/files.py
create_file(conn: sqlite3.Connection, owner_user_id: int, storage_id: str, filename: str, size_bytes: int, sha256_digest: bytes, created_at: int) -> int
get_file(conn: sqlite3.Connection, file_id: int) -> dict | None
list_accessible_files(conn: sqlite3.Connection, user_id: int, role: str) -> list[dict]
grant_access(conn: sqlite3.Connection, file_id: int, user_id: int, granted_by: int, created_at: int) -> None
revoke_access(conn: sqlite3.Connection, file_id: int, user_id: int) -> None
list_file_grants(conn: sqlite3.Connection, file_id: int) -> list[dict]
delete_file(conn: sqlite3.Connection, file_id: int) -> None
list_storage_ids(conn: sqlite3.Connection) -> set[str]

# database/audit.py
log_event(conn: sqlite3.Connection, actor_user_id: int | None, action: str, file_id: int | None, outcome: str, detail_json: str, created_at: int) -> None
```

Each database function uses parameterized SQL and never commits independently. `transaction()` opens a connection with foreign keys enabled and 5-second busy timeout, begins an immediate transaction, commits on success, rolls back on exception, and closes the connection. `initialize()` is idempotent. Timestamps are UTC Unix seconds.

## 11. SQLite schema and constraints

```sql
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK(length(username) BETWEEN 1 AND 64),
    password_hash BLOB NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('Admin', 'User')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
    created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
    revoked_at INTEGER CHECK(revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE TABLE files (
    file_id INTEGER PRIMARY KEY,
    owner_user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    storage_id TEXT NOT NULL UNIQUE CHECK(length(storage_id) = 32),
    filename TEXT NOT NULL CHECK(length(CAST(filename AS BLOB)) BETWEEN 1 AND 255),
    size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 0 AND 52428800),
    sha256_digest BLOB NOT NULL CHECK(length(sha256_digest) = 32),
    created_at INTEGER NOT NULL
);

CREATE TABLE file_acl (
    file_id INTEGER NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    granted_by INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(file_id, user_id)
);

CREATE TABLE audit_logs (
    event_id INTEGER PRIMARY KEY,
    actor_user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    file_id INTEGER REFERENCES files(file_id) ON DELETE SET NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('success', 'denied', 'failure')),
    detail_json TEXT NOT NULL DEFAULT '{}'
        CHECK(json_valid(detail_json) AND length(detail_json) <= 4096),
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_sessions_user_expiry ON sessions(user_id, expires_at);
CREATE INDEX idx_files_owner_created ON files(owner_user_id, created_at DESC);
CREATE INDEX idx_acl_user_file ON file_acl(user_id, file_id);
CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_actor_created ON audit_logs(actor_user_id, created_at DESC);
```

Audit actions allowed by application code:
`login`, `logout`, `user.create`, `user.role_change`, `user.activate`, `user.deactivate`, `file.upload`, `file.download`, `file.delete`, `file.share_grant`, `file.share_revoke`.
Audit detail is safe metadata only. Audit outcomes are `success`, `denied`, or `failure`. File deletion cascades ACL grants and leaves audit records with a null `file_id`. Users are deactivated rather than deleted.

## 12. Testing and integration plan

Local `unittest` coverage must include:

- Fragmented socket reads/writes, malformed/oversized headers and JSON, truncation at header/body boundaries, size mismatch, and connection cap.
- Stalled TLS handshake, concurrent arrivals, stalled control reads/writes, stalled upload/download bodies, timeout cleanup, and exact slot release after normal completion and every error path.
- All actions, response shapes, stable errors, login/logout, session expiry/revocation, and inactive-account behavior.
- Admin/User permission matrix, ownership, grant/revocation, and non-disclosing file access errors.
- bcrypt match/mismatch; AES-GCM round-trip and modified ciphertext/nonce/AAD rejection; SHA-256 mismatch.
- SQLite constraints, foreign keys, rollback, audit atomicity, duplicate grants, and session cleanup.
- Failed-transfer cleanup, orphan cleanup, filename validation, and destination temp-file removal on failed download.
- Mutual TLS: reject untrusted server, hostname mismatch, and missing/untrusted client certificate.
- Clean virtual-environment dependency installation and end-to-end local demo.

Integration order:
1. Contract approved and frozen.
2. Member 2 implements security modules against this contract.
3. Member 3 implements SQLite, audit, Streamlit, and setup/integration docs against these interfaces.
4. Member 1 implements client/server protocol, TLS/cert tooling, storage, and bootstrap against these interfaces.
5. Integrate locally and resolve interface mismatches before expanding scope.
6. Run tests and a clean install, then complete end-to-end demo.

Documentation must cover free local setup, certificate/key generation, environment variables, key backup, startup/shutdown, tests, locally created demo accounts, upload/share/revoke/download, and troubleshooting. Never commit keys or certificates.

## 13. ₹0 cost audit

| Item | Purpose | Cost under this setup |
|---|---|---|
| Existing computer and OS | Run local application | ₹0 additional spend; assumed already available |
| Python 3.12 and standard library | Runtime, sockets/TLS, SQLite, logging, tests | Free/open source |
| `bcrypt` | Password hashing | Free/open source |
| `cryptography` | AES-GCM and local certificate generation | Free/open source |
| `streamlit` and resolved dependencies | Local dashboard | Free/open source; no hosted service used |
| SQLite | Local relational database | Included with Python; no hosted database |
| Git and existing GitHub repository | Source control and collaboration | Local Git is free; GitHub is not a runtime dependency |
| Python `unittest` | Local tests | Included with Python |
| Local browser and terminal | Demo | Use existing tools |
| Local CA, TLS certificates, AES key | Transport and at-rest encryption | Generated locally; no paid certificate/key service |
| Internet/package download | Initial dependency install if needed | Existing plan/cached packages assumed; no runtime internet after install |
| Electricity | Run existing computers | Existing household/institutional expense, not software cost |

The software and service cost is ₹0 under these assumptions. Internet and electricity are separate existing expenses. If a proposed tool/feature could introduce cost, reject it or replace it with a free local alternative.

## 14. Completion definition

The project is complete only when the team can demonstrate locally:
- Admin bootstrap and user login/logout.
- Role-based access enforcement on the server.
- Upload, encryption at rest, sharing/grant, revocation, download, integrity verification, and delete.
- Audit logging and account activation/deactivation.
- Mutual TLS with client and server verification.
- Failure-safe transfer cleanup and tested four-connection limit/timeouts.
- Clean installation, passing local tests, documented setup, and a clear demo/viva explanation.

This is a course-project implementation contract, not a claim of production readiness.
