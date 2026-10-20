"""Microsoft Graph client using app-only (client credentials) auth."""
import secrets
import string
from typing import Any, Dict, List, Optional

import httpx
import msal

from . import config

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPE = ["https://graph.microsoft.com/.default"]

_app = None  # type: Optional[msal.ConfidentialClientApplication]


class GraphError(Exception):
    pass


def _msal_app() -> msal.ConfidentialClientApplication:
    global _app
    if _app is None:
        if config.CERT_PRIVATE_KEY_PATH:
            with open(config.CERT_PRIVATE_KEY_PATH) as f:
                cred = {"private_key": f.read(), "thumbprint": config.CERT_THUMBPRINT}
        else:
            cred = config.CLIENT_SECRET
        _app = msal.ConfidentialClientApplication(
            config.CLIENT_ID,
            authority="https://login.microsoftonline.com/" + config.TENANT_ID,
            client_credential=cred,
        )
    return _app


def _token() -> str:
    # MSAL caches tokens and refreshes silently when they expire.
    result = _msal_app().acquire_token_for_client(scopes=SCOPE)
    if "access_token" not in result:
        raise GraphError("Token acquisition failed: %s" % result.get("error_description", result))
    return result["access_token"]


def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%&*?-_"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in "!@#$%&*?-_" for c in pw)):
            return pw


def _call(client: httpx.Client, method: str, path: str, **kw) -> Dict[str, Any]:
    r = client.request(method, GRAPH + path, headers={"Authorization": "Bearer " + _token()}, **kw)
    if r.status_code >= 400:
        raise GraphError("%s %s -> %s %s" % (method, path, r.status_code, r.text[:500]))
    return r.json() if r.content else {}


def _resolve_sku_ids(client: httpx.Client, wanted: List[str]) -> List[str]:
    """Accept SKU GUIDs or skuPartNumbers (e.g. SPE_E3, O365_BUSINESS_PREMIUM)."""
    skus = _call(client, "GET", "/subscribedSkus")["value"]
    by_part = {s["skuPartNumber"].lower(): s["skuId"] for s in skus}
    by_id = {s["skuId"].lower(): s["skuId"] for s in skus}
    ids = []
    for w in wanted:
        key = w.lower()
        if key in by_part:
            ids.append(by_part[key])
        elif key in by_id:
            ids.append(by_id[key])
        else:
            raise GraphError("Unknown license '%s'. Available: %s" % (w, ", ".join(sorted(by_part))))
    return ids


def create_user(req: Dict[str, Any], password: str) -> Dict[str, Any]:
    """Create the user, then (best-effort per step) licenses, groups, manager.

    Returns a result dict; 'warnings' lists any post-create step that failed.
    Raises GraphError only if the user itself could not be created.
    """
    upn = "%s@%s" % (req["username"], req["domain"])
    body = {
        "accountEnabled": True,
        "displayName": req["display_name"],
        "givenName": req["given_name"],
        "surname": req["surname"],
        "userPrincipalName": upn,
        "mailNickname": req["username"],
        "usageLocation": req["usage_location"],
        "passwordProfile": {
            "password": password,
            "forceChangePasswordNextSignIn": True,
        },
    }
    for src, dst in (("job_title", "jobTitle"), ("department", "department"),
                     ("office_location", "officeLocation"), ("mobile_phone", "mobilePhone")):
        if req.get(src):
            body[dst] = req[src]

    warnings = []  # type: List[str]
    with httpx.Client(timeout=30) as client:
        user = _call(client, "POST", "/users", json=body)
        uid = user["id"]

        if req.get("manager_upn"):
            try:
                _call(client, "PUT", "/users/%s/manager/$ref" % uid,
                      json={"@odata.id": "%s/users/%s" % (GRAPH, req["manager_upn"])})
            except GraphError as e:
                warnings.append("manager: %s" % e)

        if req.get("licenses"):
            try:
                ids = _resolve_sku_ids(client, req["licenses"])
                _call(client, "POST", "/users/%s/assignLicense" % uid,
                      json={"addLicenses": [{"skuId": i, "disabledPlans": []} for i in ids],
                            "removeLicenses": []})
            except GraphError as e:
                warnings.append("licenses: %s" % e)

        for group in req.get("groups") or []:
            try:
                gid = group
                if len(group) != 36:  # not a GUID -> look up by display name
                    found = _call(client, "GET", "/groups",
                                  params={"$filter": "displayName eq '%s'" % group.replace("'", "''")})["value"]
                    if len(found) != 1:
                        raise GraphError("group '%s' matched %d results" % (group, len(found)))
                    gid = found[0]["id"]
                _call(client, "POST", "/groups/%s/members/$ref" % gid,
                      json={"@odata.id": "%s/directoryObjects/%s" % (GRAPH, uid)})
            except GraphError as e:
                warnings.append("group %s: %s" % (group, e))

    return {"object_id": uid, "user_principal_name": upn, "warnings": warnings}
