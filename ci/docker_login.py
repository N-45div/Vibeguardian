"""Log Docker in to Artifact Registry with the job's Google identity.

Writes the registry entry straight into ~/.docker/config.json, so the
short-lived token never passes through stdout or the job log.

    python ci/docker_login.py us-central1-docker.pkg.dev
"""

import base64
import json
import sys
from pathlib import Path

import google.auth
import google.auth.transport.requests

host = sys.argv[1]
credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
credentials.refresh(google.auth.transport.requests.Request())
config_file = Path.home() / ".docker" / "config.json"
config = json.loads(config_file.read_text()) if config_file.exists() else {}
auth = base64.b64encode(f"oauth2accesstoken:{credentials.token}".encode()).decode()
config.setdefault("auths", {})[host] = {"auth": auth}
config_file.parent.mkdir(parents=True, exist_ok=True)
config_file.write_text(json.dumps(config))
print(f"docker is logged in to {host}")
