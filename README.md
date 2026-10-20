# M365 Provisioner

Claude reads a help desk ticket, POSTs the new-user parameters here, a human clicks **Approve**
(later: `AUTO_APPROVE=true`), the service creates the user in M365 via Microsoft Graph, and Claude
polls for the result JSON to paste into the ticket reply.

```
ticket -> Claude -> POST /api/requests -> [pending] -> Approve button -> Graph -> [completed]
                                                                          Claude <- GET /api/requests/{id}
```

## 1. Entra app registration (unattended auth)

1. Entra admin center -> App registrations -> New. Single tenant. Note **Tenant ID** and **Client ID**.
2. API permissions -> Microsoft Graph -> **Application** permissions:
   - `User.ReadWrite.All` (create user, set manager, assign license)
   - `GroupMember.ReadWrite.All` (add to groups)
   - `Organization.Read.All` (resolve license names like `SPE_E3`)
   - then **Grant admin consent**.
3. Credentials: prefer a **certificate** (set `CERT_PRIVATE_KEY_PATH` + `CERT_THUMBPRINT`); a client secret
   (`CLIENT_SECRET`) works but expires. No user sign-in or MFA is involved: this is the client-credentials flow.
4. Limits to know: an app-only token cannot create/modify users holding privileged admin roles, and it
   can't add members to role-assignable groups without extra permission. That is a useful guardrail.

## 2. Run

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
export TENANT_ID=... CLIENT_ID=... CERT_PRIVATE_KEY_PATH=... CERT_THUMBPRINT=...
export DEFAULT_DOMAIN=yourcompany.com API_KEY=$(openssl rand -hex 32) UI_PASSWORD='long-random'
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Docker

All settings come from environment variables; the SQLite DB lives in the `/data` volume.

```bash
cp .env.example .env   # fill in values
docker compose up -d --build
# or: docker build -t m365-provisioner . && docker run -d -p 8000:8000 --env-file .env -v provisioner-data:/data m365-provisioner
```

For certificate auth, either set `CERT_PRIVATE_KEY` to the PEM (newlines may be written as `\n`) or mount
the file and set `CERT_PRIVATE_KEY_PATH`. Together with `CERT_THUMBPRINT`.

Put it behind HTTPS (IIS/ARR, nginx, Caddy) - API keys and the temp password travel in the clear otherwise.
Set `DRY_RUN=true` first to try the whole flow without touching M365.

| Variable | Purpose |
|---|---|
| `AUTO_APPROVE` | `false` = human click required (default). `true` = created immediately on submit. |
| `DRY_RUN` | Never calls Graph. |
| `ALLOWED_DOMAINS` | Comma list of UPN domains the agent may use. |
| `DEFAULT_USAGE_LOCATION` | Needed for licensing (2-letter code). |
| `API_KEY` | Secret Claude sends as `X-API-Key` or `Authorization: Bearer`. |
| `UI_USERNAME` / `UI_PASSWORD` | Basic-auth login for approvers. |

## 3. Agent contract

Submit:
```bash
curl -X POST https://provisioner.internal/api/requests -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d '{
  "ticket_id": "1042", "given_name": "Jane", "surname": "Doe", "username": "jane.doe",
  "job_title": "Analyst", "department": "Finance", "manager_upn": "boss@yourcompany.com",
  "licenses": ["SPE_E3"], "groups": ["Finance Team"]
}'
```
Only `ticket_id`, `given_name`, `surname`, `username` are required. Submitting the same `ticket_id` twice
returns the existing request instead of creating a duplicate (rejected/failed ones can be resubmitted).
If `password` is omitted the server generates one; the user must change it at first sign-in.

Poll `GET /api/requests/{id}` until `status` is `completed`, `failed` or `rejected`:
```json
{ "id": "…", "ticket_id": "1042", "status": "completed",
  "result": { "username": "jane.doe", "user_principal_name": "jane.doe@yourcompany.com",
              "object_id": "…", "must_change_password": true, "warnings": [],
              "temporary_password": "…" } }
```
`temporary_password` is returned **once**, then erased from the database. `warnings` lists any post-create
step (manager/license/group) that failed while the user itself was created.

## Security notes

- The password never appears in the UI or list endpoints. Consider sending it to the user by a channel other
  than a ticket reply if your tickets are visible to many people (or post a private note instead of a public reply).
- Approve/reject POSTs reject cross-site requests (browsers auto-send Basic auth). Next step for production:
  swap Basic auth for Entra ID SSO so approvals are attributable to individuals and covered by Conditional Access.
- Before enabling `AUTO_APPROVE`, run in manual mode for a while, and keep `ALLOWED_DOMAINS` and the app's
  Graph permissions as narrow as possible. Consider allow-listing licenses/groups the agent may request.
- Audit: every request keeps the payload, approver, timestamps and result in `provisioner.db`.
