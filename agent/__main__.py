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
from pathlib import Path

import psutil

STATE = Path(os.getenv("MERIDIAN_AGENT_STATE", "agent.json"))


def request(controller: str, path: str, payload: dict, method: str = "POST", key: str | None = None) -> dict:
    body=json.dumps(payload).encode()
    req=urllib.request.Request(controller.rstrip("/")+path,data=body,method=method,headers={"Content-Type":"application/json"})
    if key: req.add_header("X-Meridian-Agent-Key",key)
    with urllib.request.urlopen(req,timeout=20) as res: return json.loads(res.read())


def inventory() -> dict:
    disk=shutil.disk_usage(Path.cwd())
    return {"cpu_count":psutil.cpu_count(logical=True) or 1,"memory_bytes":psutil.virtual_memory().total,"disk_bytes":disk.total,"python":platform.python_version(),"kernel":platform.release()}


def posture() -> dict:
    system=platform.system().lower()
    checks={"admin_user":os.name=="nt" or hasattr(os,"geteuid") and os.geteuid()==0}
    if system=="linux":
        checks["firewall"] = shutil.which("ufw") is not None or shutil.which("firewalld") is not None
        checks["package_manager"] = any(shutil.which(x) for x in ("apt-get","dnf","yum"))
        checks["systemd"] = shutil.which("systemctl") is not None
    if system=="windows":
        checks["powershell"] = shutil.which("powershell.exe") is not None or shutil.which("pwsh.exe") is not None
        checks["service_control"] = shutil.which("sc.exe") is not None
    return checks


def patch_assessment() -> dict:
    system=platform.system().lower()
    if system=="linux":
        if shutil.which("apt-get"):
            out=subprocess.run(["apt-get","-s","upgrade"],capture_output=True,text=True,timeout=30)
            return {"manager":"apt","simulation_exit_code":out.returncode,"summary":out.stdout[-12000:]}
        if shutil.which("dnf"):
            out=subprocess.run(["dnf","check-update"],capture_output=True,text=True,timeout=30)
            return {"manager":"dnf","exit_code":out.returncode,"summary":out.stdout[-12000:]}
        if shutil.which("yum"):
            out=subprocess.run(["yum","check-update"],capture_output=True,text=True,timeout=30)
            return {"manager":"yum","exit_code":out.returncode,"summary":out.stdout[-12000:]}
    if system=="windows":
        pw=shutil.which("powershell.exe") or shutil.which("pwsh.exe")
        if pw:
            out=subprocess.run([pw,"-NoProfile","-Command","Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 50 | ConvertTo-Json -Compress"],capture_output=True,text=True,timeout=30)
            return {"manager":"windows-update-history","exit_code":out.returncode,"hotfixes":out.stdout[-12000:]}
    return {"manager":"unsupported","summary":"No supported patch assessment adapter was found."}


def service(action: str, name: str) -> dict:
    if platform.system().lower()=="windows":
        cmd={"service_start":"start","service_stop":"stop"}[action] if action!="service_restart" else "restart"
        if cmd=="restart":
            a=subprocess.run(["sc.exe","stop",name],capture_output=True,text=True,timeout=30); b=subprocess.run(["sc.exe","start",name],capture_output=True,text=True,timeout=30)
            return {"returncode":max(a.returncode,b.returncode),"stdout":a.stdout+b.stdout,"stderr":a.stderr+b.stderr}
        r=subprocess.run(["sc.exe",cmd,name],capture_output=True,text=True,timeout=30); return {"returncode":r.returncode,"stdout":r.stdout,"stderr":r.stderr}
    cmd={"service_start":"start","service_stop":"stop","service_restart":"restart"}[action]
    r=subprocess.run(["systemctl",cmd,name],capture_output=True,text=True,timeout=30); return {"returncode":r.returncode,"stdout":r.stdout,"stderr":r.stderr}


def execute(job: dict) -> tuple[str,dict]:
    action=job["action"]; params=job.get("params",{})
    if action.startswith("service_"):
        r=service(action,params["service"]); return ("succeeded" if r["returncode"]==0 else "failed",r)
    if action=="refresh_inventory": return "succeeded",{"inventory":inventory()}
    if action=="collect_diagnostics": return "succeeded",{"hostname":socket.gethostname(),"platform":platform.platform(),"cpu":psutil.cpu_percent(interval=.3),"memory":psutil.virtual_memory().percent,"uptime":max(0,int(time.time()-psutil.boot_time()))}
    if action=="assess_patches": return "succeeded",{"assessment":patch_assessment()}
    if action=="apply_security_patches":
        if platform.system().lower()=="linux":
            if shutil.which("dnf"): cmd=["dnf","-y","upgrade","--security"]
            elif shutil.which("yum"): cmd=["yum","-y","update","--security"]
            elif shutil.which("apt-get"): cmd=["apt-get","-y","upgrade"]
            else: return "failed",{"message":"No supported Linux package manager found."}
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=1800); return ("succeeded" if r.returncode==0 else "failed",{"returncode":r.returncode,"stdout":r.stdout[-12000:],"stderr":r.stderr[-12000:]})
        return "failed",{"message":"Security patch application is not implemented for this platform yet."}
    if action=="reboot":
        subprocess.Popen(["shutdown","/r","/t","0"] if platform.system().lower()=="windows" else ["systemctl","reboot"]); return "succeeded",{"message":"reboot requested"}
    if action=="shutdown":
        subprocess.Popen(["shutdown","/s","/t","0"] if platform.system().lower()=="windows" else ["systemctl","poweroff"]); return "succeeded",{"message":"shutdown requested"}
    return "failed",{"message":"unsupported action"}


def register(controller: str, enrollment: str, name: str) -> dict:
    payload={"enrollment_token":enrollment,"name":name,"hostname":socket.gethostname(),"platform":platform.system(),"arch":platform.machine(),"os_version":platform.version()}
    state=request(controller,"/api/agent/register",payload); STATE.write_text(json.dumps(state,indent=2),encoding="utf-8");
    try: STATE.chmod(0o600)
    except OSError: pass
    return state


def run(controller: str, state: dict) -> None:
    key=state["agent_key"]; interval=int(state.get("heartbeat_seconds",15))
    while True:
        hb={"hostname":socket.gethostname(),"platform":platform.system(),"arch":platform.machine(),"os_version":platform.version(),"cpu":psutil.cpu_percent(interval=.2),"memory":psutil.virtual_memory().percent,"disk":psutil.disk_usage(Path.cwd()).percent,"uptime":max(0,int(time.time()-psutil.boot_time())),"inventory":inventory(),"posture":posture()}
        try:
            request(controller,"/api/agent/heartbeat",hb,key=key)
            polled=request(controller,"/api/agent/jobs/poll",{},key=key)
            if polled.get("job"):
                job=polled["job"]
                try: st,res=execute(job)
                except Exception as exc: st,res="failed",{"error":str(exc)}
                request(controller,f"/api/agent/jobs/{job['id']}/report",{"status":st,"result":res},key=key)
        except (urllib.error.URLError,TimeoutError,OSError) as exc:
            print(f"Meridian communication error: {exc}")
        time.sleep(interval)


def main() -> None:
    p=argparse.ArgumentParser(description="Glowhaven Meridian server agent"); p.add_argument("--controller",required=True); p.add_argument("--enrollment-token"); p.add_argument("--name",default=socket.gethostname()); a=p.parse_args()
    state=register(a.controller,a.enrollment_token,a.name) if a.enrollment_token else (json.loads(STATE.read_text()) if STATE.exists() else None)
    if not state: raise SystemExit("Provide --enrollment-token for first registration.")
    run(a.controller,state)

if __name__=="__main__": main()
