from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import psutil

STATE = Path(os.getenv("ATLAS_AGENT_STATE", "agent.json"))


def request(controller: str, path: str, payload: dict, method: str = "POST", key: str | None = None) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(controller.rstrip("/") + path, data=body, method=method, headers={"Content-Type": "application/json"})
    if key:
        req.add_header("X-Atlas-Agent-Key", key)
    with urllib.request.urlopen(req, timeout=20) as res:
        date_header = res.headers.get("Date")
        if date_header:
            try:
                from email.utils import parsedate_to_datetime
                server_time = parsedate_to_datetime(date_header)
                skew = abs((datetime.now(timezone.utc) - server_time).total_seconds())
                if skew > 300:
                    print(f"Atlas warning: clock skew of {skew:.1f}s detected with controller")
            except Exception:
                pass
        return json.loads(res.read())


def inventory() -> dict:
    disk = shutil.disk_usage(Path.cwd())
    return {
        "cpu_count": psutil.cpu_count(logical=True) or 1,
        "memory_bytes": psutil.virtual_memory().total,
        "disk_bytes": disk.total,
        "python": platform.python_version(),
        "kernel": platform.release()
    }


def posture() -> dict:
    system = platform.system().lower()
    checks = {"admin_user": os.name == "nt" or hasattr(os, "geteuid") and os.geteuid() == 0}
    if system == "linux":
        checks["firewall"] = shutil.which("ufw") is not None or shutil.which("firewalld") is not None or shutil.which("nft") is not None
        checks["package_manager"] = any(shutil.which(x) for x in ("apt-get", "dnf", "yum", "zypper"))
        checks["systemd"] = shutil.which("systemctl") is not None
    if system == "windows":
        checks["powershell"] = shutil.which("powershell.exe") is not None or shutil.which("pwsh.exe") is not None
        checks["service_control"] = shutil.which("sc.exe") is not None
    return checks


def linux_package_manager() -> str | None:
    for mgr in ("apt-get", "dnf", "yum", "zypper"):
        if shutil.which(mgr):
            return mgr
    return None


def linux_package_list() -> dict:
    mgr = linux_package_manager()
    if mgr == "apt-get":
        res = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], capture_output=True, text=True, timeout=60)
        pkgs = {}
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines()[:5000]:
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    pkgs[parts[0]] = parts[1]
        return {"manager": "apt", "package_count": len(pkgs), "packages": pkgs}
    elif mgr in ("dnf", "yum"):
        res = subprocess.run([mgr, "list", "installed"], capture_output=True, text=True, timeout=60)
        pkgs = {}
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines()[1:5000]:
                parts = line.split()
                if len(parts) >= 2:
                    pkgs[parts[0]] = parts[1]
        return {"manager": mgr, "package_count": len(pkgs), "packages": pkgs}
    elif mgr == "zypper":
        res = subprocess.run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"], capture_output=True, text=True, timeout=60)
        pkgs = {}
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines()[:5000]:
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    pkgs[parts[0]] = parts[1]
        return {"manager": "zypper", "package_count": len(pkgs), "packages": pkgs}
    return {"manager": "unsupported", "package_count": 0, "packages": {}}


def linux_package_action(action: str, package: str) -> dict:
    mgr = linux_package_manager()
    if not mgr:
        return {"returncode": 1, "stdout": "", "stderr": "No supported Linux package manager found."}

    if mgr == "apt-get":
        cmd_map = {"package_install": ["apt-get", "-y", "install", package], "package_remove": ["apt-get", "-y", "remove", package], "package_update": ["apt-get", "-y", "install", "--only-upgrade", package]}
    elif mgr in ("dnf", "yum"):
        cmd_map = {"package_install": [mgr, "-y", "install", package], "package_remove": [mgr, "-y", "remove", package], "package_update": [mgr, "-y", "update", package]}
    elif mgr == "zypper":
        cmd_map = {"package_install": ["zypper", "--non-interactive", "install", package], "package_remove": ["zypper", "--non-interactive", "remove", package], "package_update": ["zypper", "--non-interactive", "update", package]}
    else:
        return {"returncode": 1, "stdout": "", "stderr": "Unsupported package manager"}

    cmd = cmd_map.get(action)
    if not cmd:
        return {"returncode": 1, "stdout": "", "stderr": f"Unsupported action {action}"}

    res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    return {"manager": mgr, "action": action, "package": package, "returncode": res.returncode, "stdout": res.stdout[-12000:], "stderr": res.stderr[-12000:]}


def windows_powershell_cmd(cmd_str: str) -> tuple[int, str]:
    pw = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not pw:
        return 1, "PowerShell executable not found"
    res = subprocess.run([pw, "-NoProfile", "-NonInteractive", "-Command", cmd_str], capture_output=True, text=True, timeout=30)
    return res.returncode, res.stdout or res.stderr


def windows_event_log(params: dict) -> dict:
    log_name = params.get("log_name", "System")
    if log_name not in ("System", "Application", "Security"):
        log_name = "System"
    script = f"Get-WinEvent -LogName {log_name} -MaxEvents 20 | Select-Object TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json -Compress"
    rc, out = windows_powershell_cmd(script)
    try:
        data = json.loads(out) if rc == 0 else []
    except Exception:
        data = []
    return {"log_name": log_name, "exit_code": rc, "events": data, "raw": out[-4000:]}


def windows_local_users() -> dict:
    script = "Get-LocalUser | Select-Object Name, Enabled, LastLogon | ConvertTo-Json -Compress"
    rc, out = windows_powershell_cmd(script)
    try:
        data = json.loads(out) if rc == 0 else []
    except Exception:
        data = []
    return {"exit_code": rc, "users": data, "raw": out[-4000:]}


def windows_network_info() -> dict:
    script = "Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength | ConvertTo-Json -Compress"
    rc, out = windows_powershell_cmd(script)
    try:
        data = json.loads(out) if rc == 0 else []
    except Exception:
        data = []
    return {"exit_code": rc, "interfaces": data, "raw": out[-4000:]}


def linux_firewall_status() -> dict:
    if shutil.which("ufw"):
        res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=15)
        return {"firewall": "ufw", "enabled": "active" in res.stdout, "output": res.stdout.strip()}
    if shutil.which("firewall-cmd"):
        res = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=15)
        return {"firewall": "firewalld", "enabled": "running" in res.stdout, "output": res.stdout.strip()}
    if shutil.which("nft"):
        res = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=15)
        return {"firewall": "nftables", "enabled": res.returncode == 0, "output": res.stdout[-4000:]}
    return {"firewall": "unknown", "enabled": False, "output": "No standard Linux firewall tool detected."}


def patch_assessment() -> dict:
    system = platform.system().lower()
    if system == "linux":
        mgr = linux_package_manager()
        if mgr == "apt-get":
            out = subprocess.run(["apt-get", "-s", "upgrade"], capture_output=True, text=True, timeout=30)
            reboot_req = Path("/var/run/reboot-required").exists()
            return {"manager": "apt", "exit_code": out.returncode, "reboot_required": reboot_req, "summary": out.stdout[-12000:]}
        if mgr == "dnf":
            out = subprocess.run(["dnf", "check-update"], capture_output=True, text=True, timeout=30)
            return {"manager": "dnf", "exit_code": out.returncode, "summary": out.stdout[-12000:]}
        if mgr == "yum":
            out = subprocess.run(["yum", "check-update"], capture_output=True, text=True, timeout=30)
            return {"manager": "yum", "exit_code": out.returncode, "summary": out.stdout[-12000:]}
        if mgr == "zypper":
            out = subprocess.run(["zypper", "list-patches"], capture_output=True, text=True, timeout=30)
            return {"manager": "zypper", "exit_code": out.returncode, "summary": out.stdout[-12000:]}
    if system == "windows":
        pw = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
        if pw:
            out = subprocess.run([pw, "-NoProfile", "-Command", "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 50 | ConvertTo-Json -Compress"], capture_output=True, text=True, timeout=30)
            return {"manager": "windows-update-history", "exit_code": out.returncode, "hotfixes": out.stdout[-12000:]}
    return {"manager": "unsupported", "summary": "No supported patch assessment adapter was found."}


def service(action: str, name: str) -> dict:
    if platform.system().lower() == "windows":
        cmd = {"service_start": "start", "service_stop": "stop"}[action] if action != "service_restart" else "restart"
        if cmd == "restart":
            a = subprocess.run(["sc.exe", "stop", name], capture_output=True, text=True, timeout=30)
            b = subprocess.run(["sc.exe", "start", name], capture_output=True, text=True, timeout=30)
            return {"returncode": max(a.returncode, b.returncode), "stdout": a.stdout + b.stdout, "stderr": a.stderr + b.stderr}
        r = subprocess.run(["sc.exe", cmd, name], capture_output=True, text=True, timeout=30)
        return {"returncode": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
    cmd = {"service_start": "start", "service_stop": "stop", "service_restart": "restart"}[action]
    r = subprocess.run(["systemctl", cmd, name], capture_output=True, text=True, timeout=30)
    return {"returncode": r.returncode, "stdout": r.stdout, "stderr": r.stderr}


def execute(job: dict) -> tuple[str, dict]:
    action = job["action"]
    params = job.get("params", {})
    if action.startswith("service_"):
        r = service(action, params.get("service", ""))
        return ("succeeded" if r["returncode"] == 0 else "failed", r)
    if action in ("package_install", "package_remove", "package_update"):
        if platform.system().lower() == "linux":
            r = linux_package_action(action, params.get("package", ""))
            return ("succeeded" if r.get("returncode") == 0 else "failed", r)
        return "failed", {"unsupported_reason": f"Action {action} is not supported on Windows directly"}
    if action == "package_list":
        if platform.system().lower() == "linux":
            return "succeeded", linux_package_list()
        return "failed", {"unsupported_reason": "Package list is not supported on this platform"}
    if action == "inspect_firewall":
        if platform.system().lower() == "linux":
            return "succeeded", linux_firewall_status()
        elif platform.system().lower() == "windows":
            rc, out = windows_powershell_cmd("Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress")
            return "succeeded", {"firewall": "windows-defender-firewall", "output": out}
        return "failed", {"unsupported_reason": "Firewall inspection is not supported on this platform"}
    if action == "windows_event_log":
        if platform.system().lower() == "windows":
            return "succeeded", windows_event_log(params)
        return "failed", {"unsupported_reason": "Windows Event Log inspection requires a Windows target host"}
    if action == "windows_local_users":
        if platform.system().lower() == "windows":
            return "succeeded", windows_local_users()
        return "failed", {"unsupported_reason": "Windows Local User inspection requires a Windows target host"}
    if action == "windows_network_info":
        if platform.system().lower() == "windows":
            return "succeeded", windows_network_info()
        return "failed", {"unsupported_reason": "Windows Network Info inspection requires a Windows target host"}
    if action == "refresh_inventory":
        return "succeeded", {"inventory": inventory()}
    if action == "collect_diagnostics":
        return "succeeded", {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "cpu": psutil.cpu_percent(interval=.3),
            "memory": psutil.virtual_memory().percent,
            "uptime": max(0, int(time.time() - psutil.boot_time())),
            "reboot_required": Path("/var/run/reboot-required").exists() if platform.system().lower() == "linux" else False
        }
    if action == "assess_patches":
        return "succeeded", {"assessment": patch_assessment()}
    if action == "apply_security_patches":
        if platform.system().lower() == "linux":
            mgr = linux_package_manager()
            if mgr == "dnf":
                cmd = ["dnf", "-y", "upgrade", "--security"]
            elif mgr == "yum":
                cmd = ["yum", "-y", "update", "--security"]
            elif mgr == "zypper":
                cmd = ["zypper", "--non-interactive", "patch", "--category", "security"]
            elif mgr == "apt-get":
                cmd = ["apt-get", "-y", "upgrade"]
            else:
                return "failed", {"message": "No supported Linux package manager found."}
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            reboot_req = Path("/var/run/reboot-required").exists()
            return ("succeeded" if r.returncode == 0 else "failed", {"returncode": r.returncode, "reboot_required": reboot_req, "stdout": r.stdout[-12000:], "stderr": r.stderr[-12000:]})
        return "failed", {"message": "Security patch application is not implemented for this platform yet."}
    if action == "reboot":
        subprocess.Popen(["shutdown", "/r", "/t", "0"] if platform.system().lower() == "windows" else ["systemctl", "reboot"])
        return "succeeded", {"message": "reboot requested"}
    if action == "shutdown":
        subprocess.Popen(["shutdown", "/s", "/t", "0"] if platform.system().lower() == "windows" else ["systemctl", "poweroff"])
        return "succeeded", {"message": "shutdown requested"}
    return "failed", {"message": "unsupported action"}


def register(controller: str, enrollment: str, name: str) -> dict:
    payload = {"enrollment_token": enrollment, "name": name, "hostname": socket.gethostname(), "platform": platform.system(), "arch": platform.machine(), "os_version": platform.version()}
    state = request(controller, "/api/agent/register", payload)
    STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    try:
        STATE.chmod(0o600)
    except OSError:
        pass
    return state


def run(controller: str, state: dict) -> None:
    key = state["agent_key"]
    interval = int(state.get("heartbeat_seconds", 15))
    while True:
        hb = {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "arch": platform.machine(),
            "os_version": platform.version(),
            "cpu": psutil.cpu_percent(interval=.2),
            "memory": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage(Path.cwd()).percent,
            "uptime": max(0, int(time.time() - psutil.boot_time())),
            "inventory": inventory(),
            "posture": posture()
        }
        try:
            request(controller, "/api/agent/heartbeat", hb, key=key)
            polled = request(controller, "/api/agent/jobs/poll", {}, key=key)
            if polled.get("job"):
                job = polled["job"]
                try:
                    st, res = execute(job)
                except Exception as exc:
                    st, res = "failed", {"error": str(exc)}
                request(controller, f"/api/agent/jobs/{job['id']}/report", {"status": st, "result": res}, key=key)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"Atlas communication error: {exc}")
        time.sleep(interval)


def main() -> None:
    p = argparse.ArgumentParser(description="Glowhaven Atlas server agent")
    p.add_argument("--controller", required=True)
    p.add_argument("--enrollment-token")
    p.add_argument("--name", default=socket.gethostname())
    a = p.parse_args()
    state = register(a.controller, a.enrollment_token, a.name) if a.enrollment_token else (json.loads(STATE.read_text()) if STATE.exists() else None)
    if not state:
        raise SystemExit("Provide --enrollment-token for first registration.")
    run(a.controller, state)


if __name__ == "__main__":
    main()
