# Local Streamlit dashboard

Run from the repository root after installing `requirements.txt` and provisioning the local CA, server/device certificates, and encryption key:

```powershell
python -m streamlit run ui/app.py --server.address 127.0.0.1 --server.port 8501 --browser.gatherUsageStats false
```

The dashboard calls only `client.api`. It does not import server, database, or security implementation modules. It stores the authenticated token only in Streamlit session state, masks passwords, uses the client API's verified download path, and clears local authentication state at logout or when the server rejects an expired/revoked session.

Sharing management uses usernames. Account role/status controls use numeric user IDs because the current public API does not provide a user-directory method. The current public API also has no grant-list method, so revocation asks for the grantee username.
