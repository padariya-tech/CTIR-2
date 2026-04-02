#!/usr/bin/env python3
"""
scripts/trigger_ingestion.py
────────────────────────────
Quick CLI helper to fire a manual ingestion against a running CTIR API.

Usage:
    python scripts/trigger_ingestion.py [--url http://localhost:8000]
"""

import argparse
import json
import sys
import urllib.request
import urllib.error


def trigger(base_url: str) -> None:
    url = f"{base_url.rstrip('/')}/api/v1/ingestion/trigger"
    req = urllib.request.Request(url, method="POST", headers={"Content-Type": "application/json"})

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            print(f"✅  Ingestion triggered — job_id={body.get('job_id')}")
            print(f"    {body.get('message')}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"❌  HTTP {e.code}: {body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"❌  Connection error: {e.reason}", file=sys.stderr)
        sys.exit(1)


def poll_job(base_url: str, job_id: int) -> None:
    import time
    url = f"{base_url.rstrip('/')}/api/v1/ingestion/jobs/{job_id}"
    print(f"\n⏳  Polling job {job_id} …")

    for _ in range(30):
        time.sleep(3)
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                job = json.loads(resp.read())
                status = job.get("status")
                print(
                    f"    status={status}  "
                    f"new={job.get('records_new')}  "
                    f"updated={job.get('records_updated')}  "
                    f"dupes={job.get('records_dupes')}  "
                    f"invalid={job.get('records_invalid')}"
                )
                if status in ("success", "partial", "failed"):
                    if job.get("error_message"):
                        print(f"    ⚠️  {job['error_message']}")
                    return
        except Exception as exc:
            print(f"    poll error: {exc}", file=sys.stderr)

    print("⏰  Timed out waiting for job completion.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8000", help="CTIR API base URL")
    parser.add_argument("--no-poll", action="store_true", help="Don't wait for job result")
    args = parser.parse_args()

    trigger(args.url)

    if not args.no_poll:
        # Re-fetch latest job to get id
        try:
            with urllib.request.urlopen(
                f"{args.url.rstrip('/')}/api/v1/ingestion/jobs?limit=1", timeout=5
            ) as resp:
                jobs = json.loads(resp.read())
                if jobs:
                    poll_job(args.url, jobs[0]["id"])
        except Exception:
            pass