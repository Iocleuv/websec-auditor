import ssl
from datetime import datetime, timezone
from websec_auditor.models import Finding


def check_certificate_expiry(cert: dict) -> list[Finding]:
    expiry = cert.get("notAfter")
    if not expiry:
        return []
    deadline = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry), tz=timezone.utc)
    days = (deadline - datetime.now(timezone.utc)).days
    if days < 30:
        return [Finding("tls-expiry", "medium" if days >= 0 else "high", f"Certificate expires in {days} days.", "Renew or replace the certificate as appropriate.")]
    return []
