# Zero Trust Secure File Sharing

A software-only, local application for authenticated file sharing with role-based access control, mutual TLS, encrypted storage, SHA-256 integrity verification, SQLite, audit logging, and a Streamlit dashboard. The UI talks only to the public functions in `client.api`; the server remains responsible for authentication and authorization.

The application does not require a hosted service, paid certificate, public domain, external API, or cloud account. Keep the server and dashboard on the same computer for the course demonstration. Python 3.12 is the project target; the current test environment has been Python 3.13.7, so Python 3.12 compatibility is not yet certified.

## Prerequisites

- Python 3.12 (recommended target; 3.13 may also work)
- The repository checkout
- Local disk space for the SQLite database and encrypted files
- Internet access only if you need to install the pinned free packages

All runtime state, keys, certificates, database records, and file objects belong outside the Git repository. On Windows, the default data directory is `%LOCALAPPDATA%\ZeroTrustFileSharing`; on Linux/macOS it is `~/.local/share/zero-trust-file-sharing`. Set `ZTS_DATA_DIR` to use a different absolute local directory.

## Install the pinned dependencies

From the repository root, create and activate a virtual environment, then install the pinned dependency set:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Linux/macOS, use `python3.12 -m venv .venv` and `source .venv/bin/activate` for activation. `requirements.txt` pins the direct packages and their resolved dependencies; it contains no paid or optional cloud integrations.

## Provision local certificates and the encryption key

The first setup creates a local root CA, a server certificate for `localhost`, a device certificate for this computer, and a 32-byte AES key. The functions refuse to overwrite existing outputs. Run this once from the repository root. The data directory selected here must be outside the repository.

```powershell
# Optional: choose a different absolute path outside the repository.
$env:ZTS_DATA_DIR = "$env:LOCALAPPDATA\ZeroTrustFileSharing"

python -c "import os; from pathlib import Path; from server.dev_certs import generate_development_ca, issue_server_certificate, issue_client_certificate; from security.key_store import create_encryption_key_file; d=Path(os.environ.get('ZTS_DATA_DIR') or (Path(os.environ['LOCALAPPDATA'])/'ZeroTrustFileSharing' if os.name=='nt' and os.environ.get('LOCALAPPDATA') else Path.home()/('AppData' if os.name=='nt' else '.local')/('Local' if os.name=='nt' else 'share')/('ZeroTrustFileSharing' if os.name=='nt' else 'zero-trust-file-sharing'))); c=d/'certs'; s=d/'secrets'; generate_development_ca(c/'ca.key',c/'ca.crt'); issue_server_certificate(c/'ca.key',c/'ca.crt',c/'server.key',c/'server.crt','localhost'); issue_client_certificate(c/'ca.key',c/'ca.crt',c/'client.key',c/'client.crt','local-demo-device'); create_encryption_key_file(s/'encryption.key'); print('Local certificates and encryption key created.')"
```

On Linux/macOS, set the data directory if desired with `export ZTS_DATA_DIR="$HOME/.local/share/zero-trust-file-sharing"` before running the same `python -c` command. If a certificate or key already exists, provisioning stops rather than replacing it. Back up `secrets/encryption.key` securely: losing it makes stored file contents unrecoverable. Protect and back up `certs/ca.key` as well; it is needed to issue another device certificate. Never commit either key or any certificate/private-key material.

The server and client read these optional environment overrides; unset values use the paths beneath `ZTS_DATA_DIR`:

| Variable | Default | Used by |
|---|---|---|
| `ZTS_DATA_DIR` | OS-specific local data directory above | Server and client |
| `ZTS_HOST` | `localhost` | Server bind address and client TLS hostname |
| `ZTS_PORT` | `8443` | Server and client |
| `ZTS_DB_FILE` | `<ZTS_DATA_DIR>/app.sqlite3` | Server SQLite database |
| `ZTS_STORAGE_DIR` | `<ZTS_DATA_DIR>/storage` | Server encrypted file objects |
| `ZTS_CA_CERT_FILE` | `<ZTS_DATA_DIR>/certs/ca.crt` | Server and client trust anchor |
| `ZTS_CA_KEY_FILE` | `<ZTS_DATA_DIR>/certs/ca.key` | Local certificate provisioning only |
| `ZTS_TLS_CERT_FILE` | `<ZTS_DATA_DIR>/certs/server.crt` | Server certificate |
| `ZTS_TLS_KEY_FILE` | `<ZTS_DATA_DIR>/certs/server.key` | Server private key |
| `ZTS_CLIENT_CERT_FILE` | `<ZTS_DATA_DIR>/certs/client.crt` | Client device certificate |
| `ZTS_CLIENT_KEY_FILE` | `<ZTS_DATA_DIR>/certs/client.key` | Client private key |
| `ZTS_KEY_FILE` | `<ZTS_DATA_DIR>/secrets/encryption.key` | Server AES-256-GCM key |

Do not place secrets in the repository or in Streamlit configuration. For a different local hostname, issue a server certificate whose SAN contains that hostname and set the same value in `ZTS_HOST` for both processes. Hostname and certificate verification remain enabled.

If you override any `ZTS_*` variable, set the same applicable values in both terminal sessions before starting the server and dashboard. Server-only values such as `ZTS_DB_FILE` and `ZTS_STORAGE_DIR` are not used by the dashboard.

## Start the application

Open two terminals at the repository root and activate `.venv` in each. In the first terminal, start the server:

```powershell
python -m server
```

On first startup, the server initializes SQLite and asks for the first Admin username and password if no users exist. The password is entered with terminal password masking. Startup fails safely when required keys or certificates are missing or invalid; it will not replace them.

In the second terminal, start the local dashboard:

```powershell
python -m streamlit run ui/app.py --server.address 127.0.0.1 --server.port 8501 --browser.gatherUsageStats false
```

Open `http://127.0.0.1:8501` in a browser on the same computer. Do not bind Streamlit to a public or LAN interface. The dashboard supports login/logout, accessible file listing, upload, verified download, owner/Admin deletion, username-based sharing and revocation, and Admin account creation/role/status controls. The public backend API does not expose user-directory or grant-list operations, so the UI asks for a username or numeric user ID when managing access/accounts.

The dashboard keeps the application token in Streamlit session state and never displays it. Password fields are masked and cleared on form submission. Downloaded data is presented to the browser only after `client.api.download_file` has verified its byte count and SHA-256 digest.

## Local tests

Run the suite from the repository root:

```powershell
python -m unittest discover -s tests -v
```

The tests use temporary databases, local storage, and locally generated certificates. They do not require a paid testing service. The project has been run in the current Python 3.13.7 environment; run the same setup and test commands with Python 3.12 before claiming compatibility on that version.

## Demo flow

1. Provision certificates and the encryption key, then start the server and create the first Admin account.
2. Log in to the local dashboard as Admin and create a User account.
3. Log in as a User, upload a sample file, and optionally share it with another active username.
4. Log in as the recipient, list and download the shared file, then revoke the grant as its owner or Admin.
5. Demonstrate that the recipient can no longer download it; then demonstrate Admin deletion and account role/status controls.

Stop the server with Ctrl+C. To move or restore the project data, stop the server and back up the database, storage directory, encryption key, CA key, and certificates together. Keep the private data backup access restricted; do not put it in Git.
