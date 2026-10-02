from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

SESSION_FILE = Path(os.getenv("ATLAS_CLI_SESSION", "atlas_cli.json"))


def make_request(url: str, path: str, payload: dict | None = None, method: str = "GET", cookies: dict | None = None, csrf: str | None = None) -> tuple[int, dict, dict]:
    full_url = url.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(full_url, data=data, method=method, headers={"Content-Type": "application/json"})

    if csrf:
        req.add_header("X-CSRF-Token", csrf)
    if cookies:
        cookie_header = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        req.add_header("Cookie", cookie_header)

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            resp_data = json.loads(resp.read().decode("utf-8")) if resp.headers.get_content_type() == "application/json" else {}
            res_cookies = {}
            for header, val in resp.headers.items():
                if header.lower() == "set-cookie":
                    cookie_part = val.split(";")[0]
                    if "=" in cookie_part:
                        ck, cv = cookie_part.split("=", 1)
                        res_cookies[ck.strip()] = cv.strip()
            return resp.status, resp_data, res_cookies
    except urllib.error.HTTPError as exc:
        try:
            err_data = json.loads(exc.read().decode("utf-8"))
        except Exception:
            err_data = {"detail": str(exc)}
        return exc.code, err_data, {}
    except Exception as exc:
        return 500, {"detail": str(exc)}, {}


def save_session(controller: str, cookies: dict, csrf: str) -> None:
    session_data = {"controller": controller, "cookies": cookies, "csrf": csrf}
    SESSION_FILE.write_text(json.dumps(session_data, indent=2), encoding="utf-8")


def load_session() -> dict:
    if not SESSION_FILE.exists():
        sys.exit("CLI Session not found. Please run 'atlas-cli login' first.")
    try:
        return json.loads(SESSION_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        sys.exit(f"Failed to read session file: {exc}")


def print_output(data: dict | list, json_output: bool) -> None:
    if json_output:
        print(json.dumps(data, indent=2))
    else:
        if isinstance(data, list):
            for idx, item in enumerate(data, 1):
                if isinstance(item, dict):
                    line = ", ".join([f"{k}={v}" for k, v in item.items() if k not in ("inventory", "posture", "result")])
                    print(f"[{idx}] {line}")
                else:
                    print(f"[{idx}] {item}")
        elif isinstance(data, dict):
            for k, v in data.items():
                print(f"{k}: {v}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Glowhaven Atlas Enterprise CLI")
    parser.add_argument("--controller", default="http://127.0.0.1:8800")
    parser.add_argument("--json", action="store_true", help="Format output as JSON")

    subparsers = parser.add_subparsers(dest="command", required=True)

    login_p = subparsers.add_parser("login", help="Authenticate with Atlas Controller")
    login_p.add_argument("--username", default="admin")
    login_p.add_argument("--password", required=True)

    subparsers.add_parser("servers", help="List managed server fleet")

    jobs_p = subparsers.add_parser("jobs", help="List or create jobs")
    jobs_p.add_argument("--action", choices=["list", "create"], default="list")
    jobs_p.add_argument("--server-id")
    jobs_p.add_argument("--job-action")

    patch_p = subparsers.add_parser("patch", help="Assess or deploy security patches")
    patch_p.add_argument("--server-id", required=True)
    patch_p.add_argument("--mode", choices=["assess", "apply"], default="assess")

    policy_p = subparsers.add_parser("policy", help="List policies or view drift")
    policy_p.add_argument("--mode", choices=["list", "drift"], default="list")

    comp_p = subparsers.add_parser("compliance", help="List compliance baselines or reports")
    comp_p.add_argument("--mode", choices=["baselines", "reports"], default="baselines")

    bmc_p = subparsers.add_parser("bmc", help="Manage BMC hardware nodes")
    bmc_p.add_argument("--mode", choices=["list", "power"], default="list")
    bmc_p.add_argument("--bmc-id")
    bmc_p.add_argument("--power-action", choices=["on", "off", "graceful_restart", "hard_reset"])

    subparsers.add_parser("rollouts", help="List rollout rings")
    subparsers.add_parser("audit", help="Fetch audit log events")

    args = parser.parse_args()

    if args.command == "login":
        status_code, resp, cookies = make_request(args.controller, "/api/auth/login", payload={"username": args.username, "password": args.password}, method="POST")
        if status_code != 200:
            sys.exit(f"Login failed: {resp.get('detail', 'invalid credentials')}")

        c_code, c_resp, c_cookies = make_request(args.controller, "/api/csrf", cookies=cookies)
        cookies.update(c_cookies)
        csrf = c_resp.get("csrf_token", "")
        save_session(args.controller, cookies, csrf)
        print(f"Successfully authenticated as {resp.get('username')} ({resp.get('role')})")
        return

    sess = load_session()
    controller = sess["controller"]
    cookies = sess["cookies"]
    csrf = sess["csrf"]

    if args.command == "servers":
        code, resp, _ = make_request(controller, "/api/servers", cookies=cookies)
        print_output(resp, args.json)
    elif args.command == "jobs":
        if args.action == "list":
            code, resp, _ = make_request(controller, "/api/jobs", cookies=cookies)
            print_output(resp, args.json)
        elif args.action == "create":
            if not args.server_id or not args.job_action:
                sys.exit("--server-id and --job-action are required to create a job")
            code, resp, _ = make_request(controller, f"/api/servers/{args.server_id}/jobs", payload={"action": args.job_action}, method="POST", cookies=cookies, csrf=csrf)
            print_output(resp, args.json)
    elif args.command == "patch":
        job_act = "assess_patches" if args.mode == "assess" else "apply_security_patches"
        code, resp, _ = make_request(controller, f"/api/servers/{args.server_id}/jobs", payload={"action": job_act}, method="POST", cookies=cookies, csrf=csrf)
        print_output(resp, args.json)
    elif args.command == "policy":
        path = "/api/policies" if args.mode == "list" else "/api/policies/drift"
        code, resp, _ = make_request(controller, path, cookies=cookies)
        print_output(resp, args.json)
    elif args.command == "compliance":
        path = "/api/compliance/baselines" if args.mode == "baselines" else "/api/compliance/reports"
        code, resp, _ = make_request(controller, path, cookies=cookies)
        print_output(resp, args.json)
    elif args.command == "bmc":
        if args.mode == "list":
            code, resp, _ = make_request(controller, "/api/hardware/bmc", cookies=cookies)
            print_output(resp, args.json)
        elif args.mode == "power":
            if not args.bmc_id or not args.power_action:
                sys.exit("--bmc-id and --power-action required for BMC power control")
            code, resp, _ = make_request(controller, f"/api/hardware/bmc/{args.bmc_id}/power", payload={"action": args.power_action}, method="POST", cookies=cookies, csrf=csrf)
            print_output(resp, args.json)
    elif args.command == "rollouts":
        code, resp, _ = make_request(controller, "/api/rollouts/rings", cookies=cookies)
        print_output(resp, args.json)
    elif args.command == "audit":
        code, resp, _ = make_request(controller, "/api/audit", cookies=cookies)
        print_output(resp, args.json)


if __name__ == "__main__":
    main()
