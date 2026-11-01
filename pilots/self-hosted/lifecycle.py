"""Root-only disposable Keycloak rollover; administrative credentials stay private."""

import json
import ssl
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://keycloak:8443"
REALM = "kedgeflow-pilot"


def rotate():
    config = json.loads(Path("/run/kf-spire/private/keycloak-admin.json").read_text())
    context = ssl.create_default_context(cafile="/run/pilot/keycloak-ca.pem")
    token_body = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": "kf-pilot-lifecycle-admin",
        "client_secret": config["client_secret"],
    }).encode()
    with urllib.request.urlopen(urllib.request.Request(
        f"{BASE}/realms/{REALM}/protocol/openid-connect/token", data=token_body,
    ), context=context, timeout=10) as response:
        token = json.load(response)["access_token"]

    def admin(path, body=None):
        request = urllib.request.Request(
            f"{BASE}/admin/realms/{REALM}" + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, context=context, timeout=10) as response:
            data = response.read()
            return json.loads(data) if data else None

    realm = admin("")
    components = admin("/components?type=org.keycloak.keys.KeyProvider")
    old = [c for c in components if c["providerId"] == "eddsa-generated"]
    if len(old) != 1:
        raise RuntimeError("expected one initial generated EdDSA provider")
    old = old[0]
    # Never copy stored private-key parameters from the old provider.
    config = {k: old["config"][k] for k in ("algorithm", "eddsaEllipticCurveKey")
              if k in old["config"]}
    config.update(priority=[str(int(old["config"].get("priority", ["100"])[0]) + 100)],
                  enabled=["true"], active=["true"])
    admin("/components", {
        "name": "kedgeflow-disposable-rollover", "providerId": "eddsa-generated",
        "providerType": "org.keycloak.keys.KeyProvider", "parentId": realm["id"],
        "config": config,
    })
    print(json.dumps({"status": "rotated", "provider": "eddsa-generated",
                      "method": "new higher-priority generated key provider"}))


if __name__ == "__main__":
    rotate()
