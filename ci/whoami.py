"""Smoke test for a CI job's Google identity.

Makes one call that the identity's own role allows: Cloud Run services for
the retirer and deployer (CHECK=cloud-run), metric descriptors for the
watcher, which can only read Cloud Monitoring (CHECK=monitoring), and the
first vantage service's health for the prover, which can only call those
services (CHECK=vantage). Prints which service account the job is acting as,
never a token.
"""

import os
import sys

import requests

from vibeguardian.gcp import session
from vibeguardian.vantage import id_token

project = os.environ["GCP_PROJECT_ID"]
http = session()
check = os.environ.get("CHECK", "cloud-run")
email = getattr(http.credentials, "service_account_email", None)
print(f"acting as: {email}")
if check == "vantage":
    region = os.environ["VANTAGE_REGIONS"].split()[0]
    url = f"https://vg-vantage-{os.environ['GCP_PROJECT_NUMBER']}.{region}.run.app"
    token = id_token(http, email, url)
    response = requests.get(f"{url}/health", headers={"Authorization": f"Bearer {token}"}, timeout=30)
else:
    urls = {
        "cloud-run": f"https://run.googleapis.com/v2/projects/{project}/locations/us-central1/services",
        "monitoring": f"https://monitoring.googleapis.com/v3/projects/{project}/metricDescriptors?pageSize=1",
    }
    response = http.get(urls[check])
print(f"{check} call: HTTP {response.status_code}")
sys.exit(0 if response.status_code == 200 else 1)
