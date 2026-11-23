"""Render Cron entry point: ask the live Flask service to process reminders."""
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main():
    base_url = os.environ.get("REMINDER_WEB_URL", "").strip().rstrip("/")
    token = os.environ.get("REMINDER_JOB_TOKEN", "")
    if not base_url.startswith("https://") or not token:
        print("REMINDER_WEB_URL (HTTPS) and REMINDER_JOB_TOKEN must be configured.", file=sys.stderr)
        return 2
    request = Request(
        base_url + "/internal/appointment-reminders",
        data=b"",
        headers={"Authorization": "Bearer " + token},
        method="POST",
    )
    try:
        with urlopen(request, timeout=45) as response:
            body = response.read(4096).decode("utf-8", errors="replace")
            if response.status != 200:
                print(f"Reminder endpoint returned HTTP {response.status}.", file=sys.stderr)
                return 1
            print(body)
            return 0
    except (HTTPError, URLError, TimeoutError) as error:
        print(f"Reminder job failed: {type(error).__name__}.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
