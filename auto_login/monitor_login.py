from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

import auto_login


DEFAULT_INTERVAL = 600


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(message: str) -> None:
    line = f"[{now()}] {message}"
    print(line, flush=True)
    log_file = Path(os.getenv("MONITOR_LOG_FILE", "monitor.log"))
    if not log_file.is_absolute():
        log_file = Path(__file__).with_name(str(log_file))
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def portal_url(path: str) -> str:
    base_url = os.getenv("CAMPUS_LOGIN_URL", auto_login.DEFAULT_URL)
    return urllib.parse.urljoin(base_url, path)


def build_raas_payload() -> dict[str, str]:
    username = os.getenv("CAMPUS_USERNAME", "")
    password = os.getenv("CAMPUS_PASSWORD", "")
    if not username or not password:
        raise RuntimeError("Please fill CAMPUS_USERNAME and CAMPUS_PASSWORD in .env.")
    return {
        "user": username,
        "pass": auto_login.encode_raas_password(password),
        "pool": os.getenv("CAMPUS_OPERATOR", ""),
    }


def post_json(opener: urllib.request.OpenerDirector, url: str, payload: dict[str, str]) -> dict:
    body = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) campus-monitor/1.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json,text/plain,*/*",
        },
    )
    with opener.open(req, timeout=10) as response:
        text = response.read().decode("utf-8", errors="replace")
    return json.loads(text)


def stat(opener: urllib.request.OpenerDirector, payload: dict[str, str]) -> dict:
    return post_json(opener, portal_url("api/stat.php"), payload)


def login_once(opener: urllib.request.OpenerDirector) -> tuple[bool, dict[str, str]]:
    payload = build_raas_payload()
    response = post_json(opener, portal_url("api/login.php"), payload)
    ret = response.get("ret")
    msg = response.get("msg") or ""
    log(f"login ret={ret} msg={msg}")
    if ret not in (0, 3, 121, 122):
        return False, payload

    if ret == 0:
        post_json(opener, portal_url("api/ack_auth.php"), payload)

    for attempt in range(1, 12):
        response = stat(opener, payload)
        ret = response.get("ret")
        msg = response.get("msg") or ""
        log(f"stat after login attempt={attempt} ret={ret} msg={msg}")
        if ret == 0:
            return True, payload
        if ret == 4:
            post_json(opener, portal_url("api/ack_auth.php"), payload)
        if ret not in (2, 3, 4):
            return False, payload
        time.sleep(1)
    return False, payload


def ensure_online(opener: urllib.request.OpenerDirector, payload: dict[str, str] | None) -> tuple[bool, dict[str, str] | None]:
    if payload:
        try:
            response = stat(opener, payload)
            ret = response.get("ret")
            msg = response.get("msg") or ""
            if ret == 0:
                log(f"online ret=0 msg={msg}")
                return True, payload
            log(f"offline or pending ret={ret} msg={msg}")
        except Exception as exc:
            log(f"status check failed: {exc}")

    ok, new_payload = login_once(opener)
    if ok:
        log("re-login succeeded")
    else:
        log("re-login failed")
    return ok, new_payload if ok else payload


def main() -> int:
    auto_login.load_dotenv(Path(__file__).with_name(".env"))
    parser = argparse.ArgumentParser(description="Monitor campus portal and auto re-login.")
    parser.add_argument("--interval", type=int, default=int(os.getenv("MONITOR_INTERVAL", DEFAULT_INTERVAL)))
    parser.add_argument("--once", action="store_true", help="Check once and exit.")
    args = parser.parse_args()

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    payload: dict[str, str] | None = None

    log(f"monitor started interval={args.interval}s")
    while True:
        try:
            _, payload = ensure_online(opener, payload)
        except (urllib.error.URLError, TimeoutError) as exc:
            log(f"network error: {exc}")
        except KeyboardInterrupt:
            log("monitor stopped")
            return 0
        except Exception as exc:
            log(f"monitor error: {exc}")

        if args.once:
            return 0
        time.sleep(max(args.interval, 5))


if __name__ == "__main__":
    raise SystemExit(main())
