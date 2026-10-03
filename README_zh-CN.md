# Glowhaven Atlas

[English](README.md) | [简体中文](README_zh-CN.md)

> **为需要单一运维控制平面的基础设施团队打造的服务器生命周期管理平台。**

Atlas 是一个开源、自托管的平台，用于管理 Linux 和 Windows 服务器集群，涵盖设备发现、遥测监控、日常维护、受控操作、变更审批以及审计追溯。

它的设计初衷是填补单机管理控制台与大型生命周期管理套件之间的空白：提供一个覆盖服务器从注册纳管到日常运维全生命周期的单一操作系统控制平面。

## 为什么选择 Atlas

服务器管理在设计上往往是碎片的。Windows Admin Center 为 Windows Server 和集群提供了深入的基于浏览器的管理能力；而 Red Hat Satellite 和 SUSE Manager 则侧重于集群生命周期、补丁管理、配置、合规性和大规模 Linux 管理。Canonical MAAS 在物理服务器供应和生命周期控制方面表现出色。

Atlas 采取了不同的路线：**将日常 Day 1 和 Day 2 服务器生命周期整合到一个跨平台的控制平面中，而无需以无限制的远程 Shell 访问作为基础。**

## Atlas 管理的功能范围

| 领域 | 当前方向 |
| --- | --- |
| 集群身份识别 | 服务器资产清单、操作系统身份、架构、标签、最近在线状态 |
| 遥测监控 | CPU、内存、磁盘、运行时间、组件清单、基础安全态势 |
| 补丁操作 | 跨平台补丁评估适配器以及在支持的 Linux 包管理器上受控执行安全补丁 |
| 变更控制 | 高风险操作的审批关卡 |
| 维护管理 | 具备维护窗口感知能力的作业控制 |
| 服务管理 | Linux systemd 和 Windows Service Control 操作 |
| 电源管理 | 受控的重启与关机操作 |
| 诊断工具 | 边界受限的主机诊断信息收集 |
| 设备纳管 | 一次性且带过期时间的纳管凭证 |
| 审计日志 | 结构化的操作员与 Agent 事件 |
| 部署模式 | 具有降低权限（drop capabilities）和只读文件系统的非 root 容器配置 |

## 架构

```text
                       操作员 / API 客户端
                                |
                                v
                        +----------------------+
                        |  ATLAS 控制节点      |
                        |----------------------|
                        | 身份认证             |
                        | 权限控制             |
                        | 集群状态             |
                        | 遥测数据             |
                        | 补丁编排             |
                        | 变更审批             |
                        | 作业队列             |
                        | 审计日志             |
                        +----------+-----------+
                                   |
                    +--------------+--------------+
                    |              |              |
                    v              v              v
               服务器 A        服务器 B        服务器 C
               Atlas Agent    Atlas Agent    Atlas Agent
```

当前版本采用 SQLite 以实现轻量便捷的单节点部署。代码结构经过精心设计，以便持久化层和作业执行机制可以在平台成熟时平滑演进为高可用控制器。

## 核心原则

**原生跨平台设计。** 控制节点（Controller）掌控工作流，而 Agent 掌控特定平台的具体执行。

**受限操作模型。** 优先采用服务端操作白名单，而非通用命令网关。

**变更审批控制。** 重启、关机和安全补丁应用都需要经过审批，而不是静默变为即时执行的高权操作。

**可观测状态。** 集群身份、遥测、作业和审计事件统一生活在相同的运维数据模型中。

**自托管可控。** 基础设施数据可以完全保留在组织内部网络环境中。

## 安全特性

Atlas 包含多项切实的控制措施：

- scrypt 密码哈希
- HttpOnly 和 SameSite 会话 Cookie
- CSRF 防御
- 服务端授权机制
- 可过期且一次性的纳管 Token
- 哈希化的 Agent 凭据
- 明确的操作白名单
- 严格的服务名称校验
- 安全响应头
- 非 root 容器运行
- Linux 容器 Capability 剥离
- 只读容器文件系统
- 结构化审计事件
- 自动化安全回归测试

本项目并不声称已通过安全认证、无懈可击或自动适用于所有生产环境。各组织应根据自身的部署需求，叠加 TLS 加密、身份提供者集成、受保护的备份、网络隔离、密钥管理、集中式日志记录和操作系统加固。

安全漏洞请通过 GitHub 的 **Security -> Report a vulnerability** 流程私下提交，请勿公开发布 issue。详见 [SECURITY.md](SECURITY.md)。

## 快速开始

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

打开浏览器访问 `http://127.0.0.1:8800`。

默认引导管理员用户名为 `admin`，除非修改了 `ATLAS_BOOTSTRAP_ADMIN` 环境变量。

## Docker 部署

```bash
cp .env.example .env
docker compose up --build
```

生产环境部署时，请在 Atlas 前端终止 TLS，启用安全 Cookie，将数据库持久化在受保护的存储上，并限制对管理平面的网络访问。

## 企业级 Linux 部署指南 (RHEL / Rocky Linux / AlmaLinux / Fedora)

### 在企业级 Linux 上配置 Controller 服务

1. 安装 Python 3、pip 和必需的系统依赖：
```bash
sudo dnf install -y python3 python3-pip python3-virtualenv git
```

2. 克隆仓库并配置环境：
```bash
git clone https://github.com/GlowhavenIndustries/Glowhaven-Systems-Management.git
cd Glowhaven-Systems-Management
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. 为 Atlas Controller 配置 systemd 服务 (`/etc/systemd/system/atlas-controller.service`)：
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

4. 启动并启用 Controller 服务：
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now atlas-controller
```

### 在企业级 Linux 上配置 Agent 系统服务

要在被管理的企业级 Linux 主机（RHEL / Rocky Linux / AlmaLinux / Fedora）上作为后台 systemd 服务持续运行 Agent：

1. 安装 Python 3 和依赖：
```bash
sudo dnf install -y python3 python3-pip
```

2. 创建 Agent 目录并安装所需软件包：
```bash
sudo mkdir -p /opt/glowhaven-agent
sudo chown -R root:root /opt/glowhaven-agent
cd /opt/glowhaven-agent
python3 -m venv .venv
source .venv/bin/activate
pip install requests
```

3. 创建 Agent systemd 服务配置文件 (`/etc/systemd/system/atlas-agent.service`)：
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

4. 启动并 Enable Agent 服务：
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now atlas-agent
```

## 服务器纳管注册

1. 以管理员身份登录。
2. 选择 **Add server**（添加服务器）。
3. 生成单次使用的纳管 Token。
4. 在目标服务器上安装 Agent。
5. 运行 Agent 连接到 Atlas Controller。

```bash
python -m agent --controller https://atlas.example.internal --enrollment-token <TOKEN> --name prod-web-01
```

Agent 将上报遥测数据、汇报安全态势、进行补丁评估，并轮询受批准的操作指令。

## 当前补丁模型

补丁评估基于适配器架构。

在 Linux 上，Atlas 可以使用以下可用的包管理器适配器：

- `apt-get`
- `dnf`
- `yum`

在 Windows 上，当前的 Agent 上报已安装的修补程序历史记录作为初始的 Windows 更新信号。在实现并测试安全的 Windows 更新适配器之前，Windows 安全补丁应用与 Linux 包管理器执行路径保持明确隔离。

高影响的补丁操作受审批机制保护，且必须由通过身份验证的 Agent 执行，而不是直接由 Web 浏览器触发。

## 当前局限性

Atlas 是一个演进中的开源平台。当前版本是一个坚实的实际基础，而非声称与所有成熟的管理套件具有完全相同的功能。

它目前尚不具备以下领域的完整功能：

- 裸金属 PXE 引导
- Redfish 和 BMC 生命周期管理
- 企业级 SSO 与 OIDC
- PostgreSQL 高可用架构
- 深度配置管理
- 完整合规框架
- Hypervisor 虚拟化编排
- 集群管理
- Windows 安全补丁直接安装

这些领域已列入产品路线图，未来将作为真实能力逐步实现，而非提供虚假的占位接口。

## 路线图

### 控制平面

- 基于 PostgreSQL 的持久化存储
- 高可用集群
- 持久化分布式作业队列
- 多站点边缘控制器

### 身份与权限

- OIDC 及企业级 SSO
- WebAuthn / Passkeys 密钥登录
- 细粒度 RBAC 权限控制
- 即时 (JIT) 特权访问

### 生命周期

- 完整补丁基线
- 感知重启的分阶段滚动更新
- 配置漂移管理
- 维护窗口
- 期望状态策略

### 硬件管理

- Redfish
- IPMI
- BMC 资产与电源控制
- 固件生命周期工作流

### 生态集成

- Ansible 集成
- NetBox 集成
- Prometheus 集成
- 告警与事件响应工作流
- Kubernetes 及虚拟化集成

### 企业级运维

- 审批策略引擎
- 变更窗口与封网禁运期
- Fleet Ring 部署环与分阶段发布
- 合规审计报告
- 已签名的 Agent 发布与安全更新通道

## Atlas 不是什么

Atlas 不是 Hypervisor 虚拟化平台、SIEM 日志分析系统、CMDB 资产库、Kubernetes 控制平面或任意远程 Shell 网关。

它是 **服务器生命周期控制层**，旨在与这些系统进行深度集成，而不是试图取代它们。

## 开发者体验

代码库有意保持了简洁且易于理解的模块结构：

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

运行测试：

```bash
pytest -q
```

运行语法检查：

```bash
python -m py_compile atlas/*.py agent/*.py
```

CI 工作流会自动运行测试、Python 编译验证以及依赖项审计。

## 企业评估指南

对于正在评估 Atlas 的企业组织，以下关键架构问题均在设计中得到明确解答：

**状态储存在哪里？** Controller 负责持久化集群与运维状态。

**特权操作在哪里运行？** 在通过身份验证的 Agent 上，经由白名单操作模型运行。

**变更如何进行控制？** 高风险操作必须进入审批路径，Agent 才能轮询并执行它。

**活动如何进行追踪？** 运维与安全敏感事件会记录至审计日志中。

**如何扩展？** 当前节点保持简洁；PostgreSQL、持久化分布式队列和边缘控制器均在规划中以支持更大规模部署。

**能否与现有基础设施集成？** 架构采用 API 优先和基于 Agent 的设计，未来提供与身份认证、硬件管理、监控、配置和自动化系统的集成点。

## 开源理念

Atlas 旨在保持代码的可读性、可派生性（forkable）与可扩展性。基础设施团队能够直接审查 Controller 代码、理解 Agent 工作原理、添加集成模块并适配部署模式，而无需依赖闭源的管理设备。

欢迎贡献代码。对于 Bug、兼容性报告、功能需求和架构讨论，请使用 Issues。对于安全漏洞，请使用私密安全报告工作流。

## 开源协议

MIT 协议。详见 [LICENSE](LICENSE)。
