# Glowhaven Atlas

[English](README.md) | [简体中文](README_zh-CN.md)

> **The server lifecycle platform for infrastructure teams that need one operational control plane.**

Atlas is an open-source, self-hosted platform for managing Linux and Windows server fleets across discovery, telemetry, maintenance, controlled operations, change approval, and auditability.

It is designed to occupy the space between a per-server administration console and a large lifecycle-management suite: one system for the operational layer that follows a server from enrollment through ongoing maintenance.

## Why Atlas exists

Server management is fragmented by design. Windows Admin Center provides deep browser-based administration for Windows Server and clusters, while Red Hat Satellite and SUSE Manager emphasize fleet lifecycle, patching, configuration, compliance, and large-scale Linux management. Canonical MAAS is strong at physical-server provisioning and lifecycle control.

Atlas takes a different approach: **bring the recurring Day 1 and Day 2 server lifecycle into one cross-platform control plane without requiring unrestricted remote shell access as the foundation.**

## What Atlas manages

| Area | Current direction |
| --- | --- |
| Fleet identity | Server inventory, OS identity, architecture, labels, last-seen state |
| Telemetry | CPU, memory, disk, uptime, inventory, basic security posture |
| Patch operations | Cross-platform patch assessment adapters and controlled security-patch execution on supported Linux package managers |
| Change control | Approval gates for high-impact operations |
| Maintenance | Maintenance-window aware job control |
| Services | Linux systemd and Windows Service Control operations |
| Power | Controlled reboot and shutdown |
| Diagnostics | Bounded host diagnostic collection |
| Enrollment | Expiring, single-use enrollment credentials |
| Audit | Structured operator and agent events |
| Deployment | Non-root container profile with dropped capabilities and read-only filesystem |

## Architecture

```text
                         OPERATOR / API CLIENT
                                  |
                                  v
                        +----------------------+
                        |  ATLAS CONTROL       |
                        |----------------------|
                        | Identity             |
                        | Authorization        |
                        | Fleet state          |
                        | Telemetry            |
                        | Patch orchestration  |
                        | Change approval      |
                        | Job queue            |
                        | Audit                |
                        +----------+-----------+
                                   |
                    +--------------+--------------+
                    |              |              |
                    v              v              v
               Server A       Server B       Server C
               Atlas          Atlas          Atlas
               Agent          Agent          Agent
```

The current release uses SQLite for an approachable single-node deployment. The code is structured so persistence and job execution can evolve toward a highly available controller as the platform matures.

## Core principles

**Cross-platform by design.** The controller owns the workflow while the agent owns platform-specific execution.

**Bounded operations.** Server-side action allowlists are preferred over generic command gateways.

**Change control.** Reboot, shutdown, and security patch application require approval rather than silently becoming immediate privileged actions.

**Observable state.** Fleet identity, telemetry, jobs, and audit events live in the same operational model.

**Self-hosted control.** Infrastructure data can remain inside the organization's environment.

## Security

Atlas includes real controls including:

- scrypt password hashing
- HttpOnly and SameSite session cookies
- CSRF protection
- Server-side authorization
- Expiring, single-use enrollment tokens
- Hashed agent credentials
- Explicit operation allowlists
- Strict service-name validation
- Security headers
- Non-root container execution
- Linux capability dropping
- Read-only container filesystem
- Structured audit events
- Automated security regression tests

This project does not claim to be certified, invulnerable, or automatically production-ready for every environment. Organizations should layer TLS, identity-provider integration, protected backups, network segmentation, secrets management, centralized logging, and operating-system hardening appropriate to their deployment.

Security vulnerabilities should be submitted privately through GitHub's **Security -> Report a vulnerability** workflow rather than public issues. See [SECURITY.md](SECURITY.md).

## Quick start

```bash
git clone https://github.com/GlowhavenIndustries/Glowhaven-Systems-Management.git
cd Glowhaven-Systems-Management
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1
$env:ATLAS_BOOTSTRAP_PASSWORD = "replace-with-a-long-random-password"

# Linux / macOS
source .venv/bin/activate
export ATLAS_BOOTSTRAP_PASSWORD="replace-with-a-long-random-password"

pip install -r requirements-dev.txt
uvicorn atlas.main:app --host 127.0.0.1 --port 8800
```

Open `http://127.0.0.1:8800`.

The default bootstrap username is `admin` unless `ATLAS_BOOTSTRAP_ADMIN` is changed.

## Docker

```bash
cp .env.example .env
docker compose up --build
```

For production deployment, terminate TLS in front of Atlas, enable secure cookies, persist the database on protected storage, and restrict network access to the management plane.

## Enterprise Linux Deployment (RHEL / Rocky Linux / AlmaLinux / Fedora)

### Controller Setup on Enterprise Linux

1. Install Python 3, pip, and required system dependencies:
```bash
sudo dnf install -y python3 python3-pip python3-virtualenv git
```

2. Clone repository and setup environment:
```bash
git clone https://github.com/GlowhavenIndustries/Glowhaven-Systems-Management.git
cd Glowhaven-Systems-Management
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Configure systemd service for Atlas Controller (`/etc/systemd/system/atlas-controller.service`):
```ini
[Unit]
Description=Glowhaven Atlas Controller
After=network.target

[Service]
Type=simple
User=atlas
Group=atlas
WorkingDirectory=/opt/glowhaven-atlas
Environment="ATLAS_BOOTSTRAP_PASSWORD=replace-with-a-long-random-password"
ExecStart=/opt/glowhaven-atlas/.venv/bin/uvicorn atlas.main:app --host 127.0.0.1 --port 8800
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

4. Enable and start the controller service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now atlas-controller
```

### Agent Setup as a Systemd Service on Enterprise Linux

To run the agent continuously as a background systemd service on managed Enterprise Linux hosts (RHEL / Rocky Linux / AlmaLinux / Fedora):

1. Install Python 3 and dependencies:
```bash
sudo dnf install -y python3 python3-pip
```

2. Create an agent directory and install requirements:
```bash
sudo mkdir -p /opt/glowhaven-agent
sudo chown -R root:root /opt/glowhaven-agent
cd /opt/glowhaven-agent
python3 -m venv .venv
source .venv/bin/activate
pip install requests
```

3. Create the agent systemd service unit (`/etc/systemd/system/atlas-agent.service`):
```ini
[Unit]
Description=Glowhaven Atlas Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/glowhaven-agent
ExecStart=/opt/glowhaven-agent/.venv/bin/python3 -m agent --controller https://atlas.example.internal --enrollment-token <TOKEN> --name prod-web-01
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

4. Enable and start the agent service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now atlas-agent
```

## Enroll a server

1. Sign in as an administrator.
2. Select **Add server**.
3. Generate a single-use enrollment token.
4. Install the agent on the target server.
5. Run the agent against the Atlas controller.

```bash
python -m agent --controller https://atlas.example.internal --enrollment-token <TOKEN> --name prod-web-01
```

The agent sends telemetry, reports security posture, performs patch assessment, and polls for approved operations.

## Current patch model

Patch assessment is adapter-based.

On Linux, Atlas can use available package-manager adapters for:

- `apt-get`
- `dnf`
- `yum`

On Windows, the current agent reports installed hotfix history as the first Windows update signal. Windows security-patch application remains intentionally separated from the Linux package-manager execution path until a safe Windows update adapter is implemented and tested.

High-impact patch operations are approval-gated and must be executed by the authenticated agent rather than directly by the web browser.

## Current limitations

Atlas is an evolving open-source platform. The present release is a real working foundation, not a claim to full feature parity with every established management suite.

It does not yet provide the full breadth of:

- Bare-metal PXE provisioning
- Redfish and BMC lifecycle management
- Enterprise SSO and OIDC
- PostgreSQL high availability
- Deep configuration management
- Full compliance frameworks
- Hypervisor orchestration
- Cluster management
- Windows security-patch installation

Those areas belong in the product roadmap and should be implemented as real capabilities rather than represented by placeholder interfaces.

## Roadmap

### Control plane

- PostgreSQL-backed persistence
- High availability
- Durable distributed job queue
- Multi-site edge controllers

### Identity

- OIDC and enterprise SSO
- WebAuthn / passkeys
- Fine-grained RBAC
- Just-in-time privileged access

### Lifecycle

- Full patch baselines
- Reboot-aware staged rollouts
- Configuration drift management
- Maintenance windows
- Desired-state policies

### Hardware

- Redfish
- IPMI
- BMC inventory and power control
- Firmware lifecycle workflows

### Ecosystem

- Ansible integration
- NetBox integration
- Prometheus integration
- Alerting and incident workflows
- Kubernetes and virtualization integrations

### Enterprise operations

- Approval policy engine
- Change windows and blackout periods
- Fleet rings and staged deployments
- Compliance reporting
- Signed agent releases and secure update channels

## What Atlas is not

Atlas is not a hypervisor, SIEM, CMDB, Kubernetes control plane, or arbitrary remote-shell gateway.

It is the **server lifecycle control layer** that can integrate with those systems rather than pretending to replace all of them.

## Developer experience

The codebase intentionally uses a small number of understandable components:

```text
Glowhaven-Systems-Management/
├── atlas/
│   ├── main.py
│   ├── config.py
│   ├── db.py
│   ├── security.py
│   └── static/
├── agent/
│   └── __main__.py
├── tests/
├── .github/workflows/ci.yml
├── Dockerfile
├── docker-compose.yml
├── SECURITY.md
├── pyproject.toml
└── requirements.txt
```

Run tests with:

```bash
pytest -q
```

Run syntax validation with:

```bash
python -m py_compile atlas/*.py agent/*.py
```

CI runs tests, Python compilation validation, and dependency auditing.

## Enterprise evaluation

For organizations evaluating Atlas, the important architectural questions are explicit:

**Where does state live?** The controller persists fleet and operational state.

**Where do privileged actions run?** On authenticated agents through an allowlisted action model.

**How are changes controlled?** High-impact work enters an approval path before an agent can poll it.

**How is activity tracked?** Operational and security-sensitive events are written to the audit log.

**How does it scale?** The current node is intentionally simple; PostgreSQL, durable distributed queues, and edge controllers are planned for larger deployments.

**Can it integrate with existing infrastructure?** The architecture is API-first and agent-based, with future integration points for identity, hardware management, monitoring, configuration, and automation systems.

## Open source

Atlas is designed to be readable, forkable, and extensible. Infrastructure teams should be able to inspect the controller, understand the agent, add an integration, and adapt the deployment model without depending on a closed management appliance.

Contributions are welcome. Use issues for bugs, compatibility reports, feature requests, and architecture discussions. Use the private security reporting workflow for vulnerabilities.

## License

MIT. See [LICENSE](LICENSE).
