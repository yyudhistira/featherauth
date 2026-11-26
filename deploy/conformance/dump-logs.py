"""Saves the log of every test module the suite holds to /out/logs, so a failing
run can be read after the containers are gone."""
import json
import os
import sys

import httpx

base = os.environ["CONFORMANCE_SERVER"].rstrip("/")
out = "/out/logs"
os.makedirs(out, exist_ok=True)
with httpx.Client(verify=False, timeout=60) as c:
    info = c.get(base + "/api/log", params={"length": 1000, "public": "false"}).json()
    for item in info.get("data", []):
        tid = item["testId"]
        log = c.get(base + "/api/log/" + tid).json()
        with open(os.path.join(out, "%s-%s.json" % (item.get("testName", "test"), tid)), "w") as f:
            json.dump({"info": item, "log": log}, f)
sys.exit(0)
