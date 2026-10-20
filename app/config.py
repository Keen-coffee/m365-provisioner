import os


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# Entra app registration (client credentials flow, no human sign-in)
TENANT_ID = os.getenv("TENANT_ID", "")
CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")  # or use a certificate:
CERT_PRIVATE_KEY_PATH = os.getenv("CERT_PRIVATE_KEY_PATH", "")
CERT_THUMBPRINT = os.getenv("CERT_THUMBPRINT", "")

# Tenant defaults
DEFAULT_DOMAIN = os.getenv("DEFAULT_DOMAIN", "contoso.com")
ALLOWED_DOMAINS = [d.strip().lower() for d in os.getenv("ALLOWED_DOMAINS", DEFAULT_DOMAIN).split(",") if d.strip()]
DEFAULT_USAGE_LOCATION = os.getenv("DEFAULT_USAGE_LOCATION", "US")

# Behaviour
# AUTO_APPROVE=false -> a human must click Approve. Flip to true for full automation.
AUTO_APPROVE = _bool("AUTO_APPROVE", False)
# DRY_RUN=true -> never calls Graph; returns a fake result. Use for testing.
DRY_RUN = _bool("DRY_RUN", False)

# Auth for the agent (API) and for approvers (web UI)
API_KEY = os.getenv("API_KEY", "")
UI_USERNAME = os.getenv("UI_USERNAME", "admin")
UI_PASSWORD = os.getenv("UI_PASSWORD", "")

DB_PATH = os.getenv("DB_PATH", "provisioner.db")
