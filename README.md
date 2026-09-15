# VMProbe

**单台 Linux 云服务器的探针系统。** 主控端是 DeepSeek Harness（DSH）插件，你在对话里说人话；
协从端是一个单文件脚本，装在服务器上替你去执行。所有变更都要过一次**人类可读的审批**，
所有执行都留下可核对的**审计链**。

```
你的对话  ──►  DSH Host 插件（vmprobe_* 工具）  ──►  SSH  ──►  Linux 服务器
              │ 风险分级 · 审批 · 计划指纹        传输层      协从端 bootstrap.sh
              │ 审计链 · 每日报告 · 脱敏                     （事实采集 · 执行）
```

---

## 1. 它解决什么问题

| 场景 | 没有它 | 有它 |
|---|---|---|
| 「帮我把这台服务器更新一下」 | 你自己 ssh 上去敲 `apt upgrade`，敲之前还得先看有多少包、要不要重启 | 模型先跑**只读检查**给出差分（「12 个包，含内核 → 需重启」），**含内核就自动升级为 R2 并要求你确认** |
| 「每天报告一次状态」 | 写 crontab + 脚本，还得自己想好日志放哪、怎么轮转 | 每天一个文件落在固定目录，**趋势 + 异常**自动算好，缺天如实报出而不是补造 |
| 「配一下免密登录」 | 手动 scp 公钥，`chmod` 忘一个就锁死自己 | 走**事务**：写 key → **另开连接验证成功** → 才切断旧连接。**任何时刻至少一条可用路径** |
| 「上次那个更新到底跑了什么？」 | 翻 shell history，还不一定记得 | 命令日志里有**解析后的真实 argv**、审批 id、退出码、输出 sha256，且被篡改能检出 |

---

## 2. ✅ 当前状态：**可以真正管理服务器了**

| 能力 | 状态 |
|---|---|
| **SSH 传输层（ssh2）** | ✅ **已实现并端到端验证**（真实协议 / 主机密钥校验 / 连接复用 / 超时 / 文件投递） |
| **免密登录事务（含撤销）** | ✅ 已实现：写 key → **另开连接验证成功** → 才切断旧连接；失败**回滚且保留旧连接**；撤销会记住原口令凭据 |
| **环境画像采集（零安装）** | ✅ 引导脚本经 SSH **stdin 投递**执行，远端只要有一个 POSIX sh |
| **心跳保活与连接健康观测** | ✅ 已实现：60s 一次、只探活跃会话、失败即标 `detached` 并记住**最初失败原因** |
| **执行后校验（verify）** | ✅ 已实现：动作声明 `expect`，执行后**真的再探测一次**并给出 `达标 / 未达标 / 未判定` 三态结论 —— "命令返回 0"与"真的做到了"分开报 |
| **运行记录落盘** | ✅ 已实现：`runs/<runId>.log` 存完整输出 + sha256；审计只留引用与摘要 |
| **取消贯通** | ✅ 已实现：中断一路传到 SSH 通道（先 TERM、再硬关），远端命令不会继续跑完；连接仍可用 |
| **动作参数接线（按发行版）** | ✅ 已实现：`securityOnly`/`exclude`/`dryRun` 真正进入 argv，不支持的分支 fail-closed |
| **掩码凭据录入（密码不进对话）** | ✅ `tools/vmprobe-cred.mjs`（交互式不回显）+ 接入 DSH 凭据库 |
| **归档与迁移（`.vmpz`）** | ✅ 已实现：**标准 zip**（能被资源管理器 / `unzip` 直接打开）+ 清单 sha256 + 导入差异预览 + 私钥强制加密；**审计密钥与私钥永不入档**（见 §5.7） |
| **审计链 HMAC 加固** | ✅ 已实现：默认自动生成密钥 → 篡改可检出**且伪造需要密钥**；旧的无密钥链照旧可验（见 §5.5） |
| 风险分级 / 审批决策 / 计划指纹（TOCTOU） | ✅ 已实现，**审批阈值真的可配**（见 §5.6） |
| 统一脱敏 / 拒密 | ✅ 已实现 |
| 每日报告按天存文件 + 定时触发 + 自动清理 | ✅ 已实现并真机验证已排程 |
| 运行日志（`logs/run.jsonl`） | ✅ 已实现：与审计分工 —— 带 `level`、给人看、不入哈希链 |
| 插件装入 DSH 并自动激活 | ✅ 已真机验证（6 个工具、4 个动作） |
| 审批服务缺失时的行为 | ✅ **插件照常加载**，R0/R1 可用，R2/R3 一律拒绝（fail-closed）；日志 / 台账 / 状态三处可见（I5 决策） |
| 客户端 UI（浏览器侧状态徽标 / 设置页） | ⛔ **受环境阻塞**（本机发行版无客户端打包器、客户端 peer 包未发布；证据见 `ISSUES.md` §12.4）。替代：结果卡片带校验结论、状态工具带配置警告、凭据走 CLI 掩码录入 |
| 协从端守护进程 / 本地定时（M4） | ⛔ **刻意推迟**：其价值全在 Linux 特有行为（unix socket / systemd / logrotate），本机无 Linux 目标 → 只能半验证，宁可不做（`ISSUES.md` §13.5） |

**真实可用的动作**：

| 动作 | 风险 | 能做什么 | 执行后怎么判定 |
|---|---|---|---|
| `probe.facts` | R0 | 采集发行版/内核/负载/磁盘/待更新/SSH 配置 | —（只读） |
| `system.update` | R1（含内核→R2） | 按发行版分流更新；支持 `securityOnly`（RHEL/SUSE）、`exclude`（RHEL/SUSE/Arch）、`dryRun`（全部） | 重探测待更新数，`0` 才叫达标 |
| `ssh.passwordless.enable` | R3 | 免密登录事务 | 校验公钥确实已落到 `authorized_keys` |
| `ssh.passwordless.disable` | R3 | 撤销免密（先验证密码可通才删密钥） | 校验该公钥已移除 |

已经跑通的验证（全部可复现，见 §8）：

```
174 项单元测试 · 插件契约（含用 DSH 自己的 schema 校验器验证） · 21 个故障推演探测点
27 项 SSH 端到端（真实协议 + 真实 authorized_keys 闭环 + 心跳三态 + verify 四情形 + 取消贯通）
12 项归档检查（含**把归档交给 PowerShell Expand-Archive 解压**的外部交叉验证）
8 项安装守卫 · 文档路径一致性 · 环境预检 · 真机加载
```

> **测试边界（诚实说明）**：SSH 端到端测试跑在**进程内的真实 ssh2 服务端**上，exec 后端是 Git 的 bash。
> 协议、认证、主机密钥、通道、文件、退出码都是真的，`bootstrap.sh` 也是真的被投递执行；
> 但"远端"是 Windows + MSYS 而非 Linux，所以**发行版相关行为（apt/systemd/StrictModes）用注入的假 os-release 与约定模拟**。
> 它证明"传输层与事务逻辑正确"，不等于"已在所有 Linux 上验证"。

---

## 3. 架构与目录

```
vmprobe/
├── packages/
│   ├── core/            纯逻辑，零 DSH 依赖（可独立单测，也可被 CLI 复用）
│   │   ├── src/risk.js           风险分级与审批决策 ★ 安全核心
│   │   ├── src/plan.js           计划构建 + 状态指纹（TOCTOU）
│   │   ├── src/params.js         动作参数校验 + 未接线即阻断
│   │   ├── src/audit.js          哈希链（规范化 JSON + 篡改可检出）
│   │   ├── src/store.js          原子写 + 机制化拒密 + id 安全校验
│   │   ├── src/redact.js         统一脱敏（审计与错误文本的唯一关口）
│   │   ├── src/reports.js        日报文件子系统（按天独立存放）
│   │   └── src/report-builder.js 报告内容（指标抽取 + 趋势 / 异常）
│   ├── catalog/         动作目录：声明式动作定义 + 严格校验加载器
│   │   └── actions/*.json        system.update / probe.facts / ssh.passwordless.enable
│   └── plugin-host/     DSH 插件
│       ├── src/index.js          name/inject/apply 入口 + 加载台账
│       ├── src/tools.js          5 个 ToolDefinition
│       ├── src/engine.js         引擎（组合 core + catalog + transport）
│       ├── src/scheduler.js      每日报告定时器（tick + 幂等）
│       └── cordis.patch.yml      包自带的挂载声明（dsh.bundle）
├── agent/bootstrap.sh   协从端：探测 / 安装 / 卸载（POSIX sh，单文件）
├── tools/               开发与运维工具（doctor / 凭据修复 / 检查套件）
├── docs/                历史验证记录
├── README.md            本文（使用说明）
├── DEVELOPMENT.md       ★ 二次开发手册（进度台账 + 扩展指南 + 路线图）
├── DESIGN.md            架构设计与设计决策（D1–D8）
└── ISSUES.md            三轮推演：27 项缺陷的证据与修法
```

---

## 4. 安装

### 4.1 主控端（装 DSH 插件）

前置：已装 DSH（`dsh` 命令可用）。

```powershell
# 1) 把插件装进 web profile。注意用 pnpm 的 link: 协议
dsh plugin --profile web add 'link:C:/Users/-/work/vmprobe/packages/plugin-host'
```

> **为什么必须用 `link:` 而不是 `file:`**
> `file:` 是**版本化拷贝**：`add` 之后源码改动**不会刷新**（再 `add` 只会说 "Already up to date"），
> 结果 profile 静默跑着旧代码。`link:` 建的是符号链接 / Junction，源码即生效。

这一步会**同时改两处**（因为本包声明了 `dsh.bundle`）：

```jsonc
// ~/.dsh/profiles/web/package.json
{
  "dependencies": { "@vmprobe/plugin-host": "link:C:/Users/-/work/vmprobe/packages/plugin-host" },
  "dsh": { "profile": { "bundles": [ "@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app",
                                     "@vmprobe/plugin-host"   // ← 自动加进来，这就是"自动激活"的机制
  ] } }
}
```

```powershell
# 2) 重启 DSH（GUI 关掉重开即可）
# 3) 验证：看加载台账
Get-Content "$env:USERPROFILE\.dsh\vmprobe\loads.jsonl"
```

台账里应该出现两条（靠 `event` 字段区分）：

```json
{"event":"load","tools":["vmprobe_catalog","vmprobe_targets","vmprobe_status","vmprobe_action","vmprobe_logs"],"storageDir":"...\\.dsh\\vmprobe","actions":3,"transport":"not-wired"}
{"event":"scheduler.started","atUtc":"08:00","tickMs":60000}
```

> **为什么要靠台账而不是日志**：`ctx.logger` 的输出既不一定进 stdout、也不一定进 DSH 日志文件。
> 实测过——只看日志根本答不上"插件到底加载了没有"。台账是唯一可靠的证据。

### 4.2 卸载（**两处都要清**）

```powershell
dsh plugin --profile web remove '@vmprobe/plugin-host'
# 然后确认 package.json 里 dependencies 与 dsh.profile.bundles 都不再含 vmprobe
node tools/doctor.mjs        # 会检查这两处的一致性
```

> ⚠️ **只删依赖、留着 `bundles` 里的名字，DSH 会因"解析不到 bundle"而启动失败** ——
> 和凭据写错一样属于"整棵树加载不出来"的致命误配置。`doctor` 会替你查出来。

### 4.3 首次使用：添加目标并录入凭据

```powershell
# ① 在主控端对话里让模型添加目标（或直接说"添加一台服务器 1.2.3.4 用户 root"）
#    模型会调 vmprobe_targets { op:"add", id:"vm-prod", hostname:"1.2.3.4", user:"root",
#                                authRef:"VMPROBE_VM_PROD_PASSWORD" }
#    注意 authRef 只填**引用名**，不是密码。

# ② 录入密码：交互式、**不回显**、需二次确认
node tools/vmprobe-cred.mjs set VMPROBE_VM_PROD_PASSWORD

# ③ 采集画像（首次会提示确认主机密钥指纹）
#    在对话里说：「采集 vm-prod 的环境画像」
```

> ⚠️ **绝不要把密码打在对话里。** DSH 会话是持久化并会被完整重放的，
> 密码一旦进对话就永久留在会话存档中，还会被后续每一轮上下文注入。
> 如果已经打过了，请改用上面的命令重新录入，并**轮换该密码**。

**主机密钥指纹（TOFU）**：首次连接时工具会返回服务器指纹（形如 `SHA256:xxx`），
并自动固定它（R1，免弹但留痕）。之后若指纹变化会**拒绝连接**并告警 ——
可能是服务器重装，也可能是中间人。你可以用 `ssh-keygen -lf` 独立核对（格式完全一致）。

```powershell
node tools/vmprobe-cred.mjs list                    # 已录入的引用名（不显示值）
node tools/vmprobe-cred.mjs check VMPROBE_X_PASSWORD # 检查能否解析
node tools/vmprobe-cred.mjs rm VMPROBE_X_PASSWORD    # 删除
```

### 4.4 协从端（装到服务器上）

**大多数情况下你不需要装任何东西。** 环境画像采集是把 `agent/bootstrap.sh`
经 SSH 的 stdin 投递过去执行的（`sh -s -- --check`），只要远端有一个 POSIX sh 就行 ——
**不要求 curl/wget/python/node**。这是刻意的设计：首次接触零安装，也就零残留。

只有需要"长期驻留/守护进程/本地定时"（M4）时才需要安装：

```sh
# 只读探测：输出环境画像 JSON（绝不写盘，任何机器上都能安全跑）
sh bootstrap.sh --check

# 自检：版本 / 权限 / 可写目录 / 有无 sha256 工具
sh bootstrap.sh --selfcheck

# 安装：**默认强制校验**完整性
sh bootstrap.sh --install /tmp/vmprobe-linux-amd64 --sha256 <64位十六进制>
sh bootstrap.sh --install /tmp/vmprobe --no-verify   # 确实要跳过时必须显式写出

# 卸载：覆盖系统级 / 用户级 / /dev/shm 三种安装位置
sh bootstrap.sh --uninstall
sh bootstrap.sh --uninstall --purge
```

安装位置按可写性三级降级：`/usr/local/lib/vmprobe` → `~/.local/lib/vmprobe` → `/dev/shm/vmprobe`
（最后一种会明确警告"重启后消失"）。

支持的发行版：debian/ubuntu · rhel/centos/rocky/alma/fedora · suse · arch/manjaro · alpine
（`ID_LIKE` 也会被识别，例如 ubuntu 落到 debian 分支）。

---

## 5. 使用

### 5.1 对话示例

装好并重启后，直接在 DSH 对话里说：

| 你说 | 实际发生 |
|---|---|
| 「你能做什么」/「VMProbe 有哪些动作」 | 调 `vmprobe_catalog`，返回动作清单 + 基础用法 |
| 「我有哪些虚拟机」 | 调 `vmprobe_targets op=list` |
| 「查看虚拟机状态」 | 调 `vmprobe_status`：连接状态、目标、审计链健康度 |
| 「更新一下系统」 | 调 `vmprobe_action`：先出计划（差分 + 影响面 + 真实 argv）→ 含内核则升为 R2 → 弹审批 |
| 「配一下免密登录」 | R3：要求你**复述目标主机名**才放行（当前会 fail-closed 阻断，机制在 M1 接线） |
| 「把日志导出来」 | `vmprobe_logs`：审计事件（已脱敏） |

**基础用法提示是双路落地的**：`vmprobe_catalog` 返回完整用法（按需拉取，不占常驻 token）；
另有极简的一段尝试注入 `ctx.systemPrompt`（该 API 签名未经核实，不可用时只记警告、不假装成功）。

### 5.2 六个工具

| 工具 | 风险 | 作用 |
|---|---|---|
| `vmprobe_catalog` | R0 | 列出可用动作 + 基础用法提示 |
| `vmprobe_targets` | R1 | 目标 CRUD。**凭据只给引用名**，并回报"是否已配置凭据" |
| `vmprobe_facts` | R0 | 环境画像（发行版/负载/磁盘/待更新/SSH 配置）；`refresh:true` 重新采集 |
| `vmprobe_status` | R0 | 连接状态 + 目标清单 + 审计链健康度 |
| `vmprobe_action` | R0→R3 | 主入口：plan → 能力检查 → 新鲜度校验 → 审批 → 执行 → 验证 |
| `vmprobe_logs` | R0 | 查询审计记录（已脱敏）+ 链校验结果 |

> 工具数量刻意保持克制：每个工具的 schema 都是每轮请求的固定前缀开销。
> "动作"收敛到 `vmprobe_action` + 目录，**新增动作不需要改插件**。

### 5.3 四个动作与风险分级

| 动作 id | 风险 | 说明 | 参数支持 |
|---|---|---|---|
| `probe.facts` | R0 | 采集环境画像（controller 侧，脚本经 stdin 投递） | — |
| `system.update` | dynamic（基线 R1） | 更新软件包；**含内核/需重启时自动升为 R2** | `dryRun` 全部；`securityOnly` RHEL/SUSE；`exclude` RHEL/SUSE/Arch |
| `ssh.passwordless.enable` | R3 | 免密登录事务（controller 侧） | — |
| `ssh.passwordless.disable` | R3 | 撤销免密（controller 侧） | `passwordRef` |

> **参数支持是按发行版区分的，这是刻意的。** 例如 Debian 的 `apt` 没有"只装安全更新"的开关，
> 所以在 Debian 上传 `securityOnly` 会被 **fail-closed 阻断**并说明原因 ——
> 而不是假装接受、然后实际执行全量升级（那正是缺陷 F2 的形态）。
> 机制上：参数是否"已接线"由**它在 argv 里有没有被引用**自动推导，
> 作者无法通过声明把未接线的参数说成已接线。

**风险级由「动作目录 + 运行时事实」决定，模型无法指定或降低它。** 这是关键不变量。

| 级 | 含义 | 审批行为 |
|---|---|---|
| R0 | 只读 | **不弹窗**，但留痕 |
| R1 | 可逆变更 | **不弹窗**，但留痕 |
| R2 | 影响面大（含内核升级、需重启） | 每次弹窗 |
| R3 | 特权且不可逆（改认证、重启、删数据） | 每次弹窗 + **要求复述目标主机名** |

> R0/R1 免弹是刻意的：全弹会导致"审批疲劳"，用户开始无脑点同意，**审批反而失效**。
> 阈值**可配**（`autoAllowUpTo` / `alwaysAskFrom`，见 §5.6），要改行为见 `DEVELOPMENT.md` 的 recipe R5。

**执行之后会**判定**，不是"返回 0 就算成功"**：动作可以声明 `verify`，
apply 之后会**真的再探测一次**并给出三态结论。例如 `system.update` 声明了
`expect { "count": 0 }` —— 命令退出码为 0 但仍有包没装成时，结果是
**"执行完成 / ★ 未达标"**，而不是一个笼统的"成功"：

```
待更新 12 → 0        ✔ 达到目标态（探测 pkg.upgradable，2 次 / 812ms）
待更新 12 → 3        ★ 未达到目标态 —— 期望 {"count":0}，实际 {"count":3}
探测未实现 / 预演    未判定（不是"通过"）
```

**审批请求只携带一句话的 `reason`**（DSH 的 `ApprovalRequest` 只有
`agent / toolName / callId / reason / signal` 五个字段，没有承载富文本的通道）。
因此富计划（差分、影响面、真实 argv）走**工具结果 + `presentCall` 渲染**，审批只带由
`core/risk.js` 生成的精炼说明。这也是为什么流程必须是"**先把计划作为一次调用返回**，
用户看到之后才谈审批"。

### 5.4 每日报告（以文件形式按天独立存放）

```
<storageDir>/reports/<targetId>/<YYYY>/<YYYY-MM-DD>.json
                 │              │        └─ 文件名只有数字与连字符（Windows 合法）
                 │              └─ 按年分片，避免单目录堆上万条目
                 └─ 已做安全校验，防路径穿越
```

默认 `storageDir = $DSH_HOME/vmprobe`（Windows 上即 `C:\Users\-\.dsh\vmprobe`）。

```jsonc
{
  "schema": "vmprobe/report/1",
  "day": "2026-09-14",
  "targetId": "t_vm",
  "createdAt": "2026-09-14T08:00:00.000Z",
  "updatedAt": "2026-09-14T20:00:00.000Z",
  "runs": [                                   // ← 一天多次运行都留在这里，不丢
    { "at": "2026-09-14T08:00:00.000Z", "status": "ok",
      "env": { "hostname": "vm-a", "os": "ubuntu", "kernel": "6.14.0" },
      "metrics": { "diskUsedPct": 43, "upgradable": 12, "securityUpgradable": 3,
                   "memUsedPct": 25, "load1": 0.42, "rebootRequired": false },
      "trend": { "deltas": { }, "anomalies": [ { "code": "security-pending" } ] },
      "audit": { "hash": "9c02…", "count": 118, "total": 4021 }   // ← 报告与审计的绑定点
    }
  ]
}
```

三条刻意的设计决定（每条都对应一个真实的坑）：

| 决定 | 原因 |
|---|---|
| **日键用 UTC** | 本地时间遇夏令时会出现"某天 08:00 不存在"（漏天）或"同一天触发两次"（撞名）。报告内部另记 ISO 时刻供人阅读 |
| **文件名绝不含冒号** | 朴素的 RFC3339 命名 `2026-09-14T08:00:00Z.json` **在 Windows 上非法**。改用 `2026-09-14.json`；顺带好处：**字典序 = 时间序**，列目录即得时间线 |
| **一天一文件 + `runs[]`** | 定时报告与手动报告可能同日发生：文件保证"每天独立存放"，数组保证不丢任何一次 |

三条边界行为：

- **缺天不补造。** DSH 没运行就是没运行，凭空生成一份"报告"是伪造数据。用 `findGaps()` 如实算出空缺，
  让上层能说"9-15 到 9-16 有 2 天没有报告"。
- **目标不可达照样落文件**，内容记 `{ "status": "unreachable", "error": "…" }`。
  否则"没有文件"既可能是没跑、也可能是跑了但连不上 —— **这两种情况的处置完全不同**。
- **没有采集能力时不写文件**（宁可不产生报告，也不产生假报告），只在审计里记一条 `report.skipped`。

**触发方式**：每 60 秒 tick 一次，判定"今天到点了吗？今天已经生成过了吗？"
不用 `interval(cb, 86400000)` 是因为固定频率会漂移、重启会错位、夏令时会算错；
短周期 tick 让**崩溃恢复是免费的**（重启后"今天还没生成"仍成立 → 自动补跑），重复触发也无副作用。

**保留策略**：近 90 天全留，更早的每月留 1 号。一天一文件 × 多目标，不清理会无限膨胀。
**M2 起它会自动跑**：调度器在每天生成报告之后顺带清理一次（幂等键就是 UTC 日键，重启后自动补跑、
重复触发无副作用）。保留天数用 `reportRetentionDays` 配（默认 90）。清理失败**不影响**报告生成，但会明确告警 ——
不会"悄悄不清理"。想手动清一次：

```powershell
node -e "import('./packages/plugin-host/src/engine.js').then(async m => { const e = m.createEngine({dir: process.env.DSH_HOME + '/vmprobe'}); console.log(await e.pruneReports({ keepDays: 90 })); })"
```

### 5.5 日志、运行记录与审计

| 文件 | 内容 |
|---|---|
| `<storageDir>/loads.jsonl` | **加载台账**：`load` / `config.effective` / `config.warning` / `scheduler.started` / `heartbeat.started` 等。排查"插件到底加载了没有"的第一手证据 |
| `<storageDir>/logs/audit.jsonl` | **命令使用日志**：逐条 exec 的哈希链（含 `prev` / `hash`）。**过统一脱敏后才落盘** |
| `<storageDir>/logs/audit.NNNN.jsonl` | 按大小（默认 8 MiB）轮转出来的历史文件。**跨文件链可校验**（轮转记录接续旧尾哈希） |
| `<storageDir>/runs/<runId>.log` | **运行记录**（M2）：单次执行的完整输出 —— 计划摘要、逐条命令、退出码、stdout/stderr、**校验结论**。默认上限 4 MiB（`maxRunBytes`），超出截断并标注 |
| `<storageDir>/targets.json` | 目标定义。**不含任何凭据**，只有 `authRef` 引用 |

**审计与运行记录的分工**（别混淆）：

```jsonc
// audit.jsonl 里只留"引用 + 摘要"，不留输出正文（否则审计会被单次输出撑爆）
{ "event": "action.run", "runId": "r_20260914T155318_78cd12",
  "runPath": "runs/r_20260914T155318_78cd12.log", "runSha256": "800a6132…", "runBytes": 738,
  "exit": 0, "verify": { "probe": "pkg.upgradable", "satisfied": true } }
```

运行记录写盘前与审计**过同一套脱敏**（两套规则必然漂移），`runId` 是文件名所以必须通过形状校验
（挡路径穿越），失败与取消**同样落盘**（失败更需要复盘）。想核对某份记录是否被改动过：

```powershell
node -e "import('./packages/plugin-host/src/engine.js').then(async m => { const e = m.createEngine({dir: process.env.DSH_HOME + '/vmprobe'}); console.log(e.verifyRunSeal({ runId: 'r_…', sha256: '…' })); })"
```

审计链的几个要点：

- **篡改可检出**：每条含 `prev`（上一条哈希）+ `hash`。改任一条，其后全部断链。
- **内存有上限**（默认 5000 条，`maxAuditRecords` 可调），完整历史在文件里。裁剪窗口后
  `verifyChain` 需要显式锚点 —— 否则会把"裁剪"误报成"篡改"。
- **脱敏保留了"曾被脱敏"的事实**：记录里有 `redactedPaths`。既看不到秘密，又**知道秘密曾经经过**。
- ⚠️ **诚实的局限**：这是**无密钥**的 sha256 链，能可靠检出意外损坏与单侧改动，
  但**挡不住**同时拥有审计目录写权限、且愿意重算整条链的攻击者。要真正抗伪证需要 **HMAC**
  （密钥放凭据库、不进归档）。**没做，也不假装做了** → 见 `ISSUES.md` §6.3。

### 5.6 配置项

在 profile 的 `cordis.patch.yml`（或用 `--patch` 叠加层）里写：
```yaml
- insert:
  - id: vmprobe-host
    name: '@vmprobe/plugin-host'
    config:
      storageDir: 'D:\vmprobe-data'   # 默认 $DSH_HOME/vmprobe（尊重 DSH_HOME 环境变量）
      reportAtUtc: '01:00'            # 日报触发时刻，**UTC**（= 北京时间 09:00），默认 08:00
      tickMs: 60000                   # 调度器检查间隔
      reportTargets: ['t_vm']         # 只对这些目标出报告；省略 = 全部
      reportRetentionDays: 90         # 日报保留天数（更早的每月留 1 号）
      dailyReport: false              # 关掉定时日报
      heartbeat: true                 # 心跳（默认开）
      heartbeatIntervalMs: 60000      # 心跳间隔
      heartbeatTimeoutMs: 5000        # 单次心跳超时
      planTtlMs: 120000               # 计划有效期（防 TOCTOU），默认 5 分钟
      maxAuditBytes: 8388608          # 审计文件轮转阈值，默认 8 MiB
      maxRunBytes: 4194304            # 单次运行记录落盘上限，默认 4 MiB
      maxAuditRecords: 5000           # 审计内存窗口上限
      auditHmac: true                 # 审计链是否加 HMAC（默认开；false = 退回纯 sha256）
      auditKeyFile: 'D:\secrets\vmprobe-audit.key'   # 审计密钥文件（默认 <storageDir>/audit-hmac.key，不存在则生成）
      runLog: true                    # 运行日志 logs/run.jsonl（默认开）
      maxRunLogBytes: 8388608         # 运行日志轮转阈值，默认 8 MiB
      autoAllowUpTo: 'R1'             # 该级及以下免弹窗（仍写审计）；R0 = 更严格
      alwaysAskFrom: 'R2'             # 该级及以上必须审批（下限，放宽也绕不过）
      echoHostnameAt: 'R3'            # 该级及以上要求复述主机名
      hostKeyPolicy: 'accept-new'     # 主机密钥策略：accept-new | strict
      loadMarkerFile: false           # 关掉加载台账
```

关于这几个键的**诚实说明**：

- `autoAllowUpTo` 在 M2 之前是**死键**（写了不生效）。现在它真的参与判定，
  并且**启动时会把实际生效的策略写进审计**（`config.effective`）—— 放宽免审批范围是安全相关改动，必须可追溯。
  默认 `R1` 下行为与之前完全一致。
- `allowRawShell` **不是开关**：T3 原始 shell 尚未实现，写 `true` 会被明确拒绝并告警，
  而不是让你以为它开着。当前所有执行都必须经过动作目录与审批。
- **审计密钥的边界**：密钥默认生成在 `<storageDir>/audit-hmac.key`（0600）。
  它**永远不会进入归档**（否则拿到归档的人就能伪造审计链）。
  但要认清一条：**密钥与审计文件放在同一个目录时，它挡不住"能读该目录的人"** ——
  想更强就把 `auditKeyFile` 指到别处（例如系统密钥目录），
  或经 `auditKey` 从凭据库注入（该路径尚未接线，见 `DEVELOPMENT.md` 技术债）。
  另外：**整段重写审计历史**无法由链自身识别（重写会抹掉 hmac 痕迹）——
  链能自证"没被局部改过"，不能自证"没被整段换过"；这条边界写在 `DESIGN.md` D15。
- **键名写错会被明确指出**：未知配置键、非法风险级、比默认更宽松的策略，都会出现在
  ① 日志、② 加载台账（`config.warning`）、③ `vmprobe_status` 的输出里。不会再出现"改了没效果但没人告诉你"。
- **没有审批服务时**（profile 里没装审批插件）：插件**照常加载**，R0/R1 照常执行，
  **R2/R3 一律拒绝**，并在上述三处显示"审批服务不可用"。这是刻意的：一个可选服务的缺失
  不该导致整棵插件树加载失败，而安全属性由**执行时**的 fail-closed 保证。

### 5.7 归档与迁移（`.vmpz`）

```powershell
# 导出（默认：目标定义 + 画像 + 日报 + 加载台账；默认脱敏档位 standard）
node tools/vmprobe-archive.mjs export vm-backup.vmpz
node tools/vmprobe-archive.mjs export vm-backup.vmpz --include-audit --include-runs --redact none
# 带私钥：必须给口令（交互式不回显；或 --passphrase-env VAR，不接受命令行明文口令）
node tools/vmprobe-archive.mjs export full.vmpz --include-secrets

# 看里面有什么（不落盘）
node tools/vmprobe-archive.mjs inspect vm-backup.vmpz

# 导入：**默认只预演**，列出 新增/一致/冲突/凭据缺口
node tools/vmprobe-archive.mjs import vm-backup.vmpz
node tools/vmprobe-archive.mjs import vm-backup.vmpz --apply              # 真正写入
node tools/vmprobe-archive.mjs import vm-backup.vmpz --apply --overwrite  # 覆盖冲突（先备份为 *.vmpz-bak）
```

四条刻意的设计：

| 设计 | 原因 |
|---|---|
| **标准 zip 容器**（自研约 200 行，零依赖） | 归档要能被**别的工具**打开（资源管理器、`unzip`、另一台机器）。测试里用 **PowerShell `Expand-Archive`** 做外部交叉验证 —— 否则"只有我自己能读"的格式也会测试通过 |
| **审计密钥与私钥永不入档** | 密钥是"抗伪造的根"，它随归档流出去 = HMAC 白做。这是**硬编码排除**，且在清单里如实记下"跳过了什么、为什么" |
| **清单逐文件 sha256** | 导入前一一核对；不符即拒绝。"尽力而为地导入半个"比拒绝更危险 |
| **默认预演 + 默认不覆盖** | 导入会动本地数据。覆盖必须显式 `--overwrite`，且**先备份** |

> 迁移后的典型动作：`import` 的预演输出会列出**凭据缺口**（例如 `t_vm → VMPROBE_VM_A_PASSWORD`），
> 用 `node tools/vmprobe-cred.mjs set <引用名>` 重新录入即可 —— 归档从不搬运密码。

---

## 6. 故障排查

**先跑这个**：

```powershell
node tools/doctor.mjs
```

它在**不启动任何服务**的前提下检查：凭据文件是否合法（写错会让 DSH 起不来）、
overlay 引用的入口文件是否存在且不是目录、profile 的 bundles 与 dependencies 是否一致、
overlay 与已安装 bundle 是否 entry id 冲突、3080 上是否有活实例。**不打印任何凭据值**。

| 症状 | 原因 | 处理 |
|---|---|---|
| **DSH 起不来，报 `plugin tree failed to load`** | **任何一条 loader entry 失败都会导致整棵树失败**。最常见是 `.credentials.yaml` 语法错 | 错误里会点名是哪个 entry。凭据问题用 `node tools/fix-credentials.mjs`（预演）→ `--apply`（带备份与逐值 sha256 保真校验） |
| 报 `duplicate loader entry id: vmprobe-host` | 插件已作为 bundle 装入 profile，你又用了 `--patch tools/overlay.yml`（同 id） | 已安装时**不要**用 overlay；开发循环改为"改源码 + 起临时实例" |
| 报 `Received protocol 'c:'` | `name` 用了裸 Windows 绝对路径 | 改成 `file:///C:/...` URL |
| 报 `ERR_UNSUPPORTED_DIR_IMPORT` | `name` 指向的是目录 | 指向**入口文件**（`…/src/index.js`）或改用包名 |
| 工具没出现 | 插件没加载 | 看 `loads.jsonl` 有没有 `event:"load"`；没有就是**没加载**（而不是工具注册失败） |
| 日报一直不生成 | 定时器没排程 / 没有采集能力 | 看 `loads.jsonl` 里有没有 `scheduler.started`；`scheduler.not-started` 说明 timer 服务不可用 |
| 改了源码但行为没变 | profile 依赖用了 `file:`（版本化拷贝） | 换成 `link:` |
| 改了源码仍没生效 | 内存里还是旧代码 | 重启 DSH（或用临时实例验证） |
| **`git push` 到 GitHub 卡住 / `Connection was reset` / `Empty reply from server`** | 本机 `github.com:443` 被连接干扰（TCP 能连、TLS 被重置）；DNS 与 hosts 都正常 | 跑 `node tools/release/diagnose-github-push.mjs` 确认；GitHub 改走 SSH（`git remote set-url origin git@github.com:Adriel-z/vmprobe.git`），发布脚本已自动优先 SSH。只剩 API 可用时用 `tools/release/push-via-api.mjs` |
| `git push` 报 `fetch first`，但内容明明一样 | 远端历史是用 REST API 通道造的，**内容相同但 commit sha 不同** | 先比 `tree`（`git rev-parse FETCH_HEAD^{tree}` 与 `HEAD^{tree}` 一致即内容相同），确认无误后 `--force` 推送本地原始历史对齐 |

**验证插件加载（不影响正在服务的实例）**：

```powershell
# --port 0 让系统自选空闲端口；--no-open 不弹浏览器；看完台账即可关掉
dsh --profile web --no-open --port 0
Get-Content "$env:USERPROFILE\.dsh\vmprobe\loads.jsonl" -Tail 3
```

> ⚠️ **不要在插件已安装时加 `--patch tools/overlay.yml`** —— entry id 冲突会让启动直接失败。

---

## 7. 安全说明

| 机制 | 做法 |
|---|---|
| **凭据不进对话** | DSH 会话是持久化并会被完整重放的，所以密码绝不该出现在聊天里。工具只接受 `authRef` 引用，密码应由掩码 UI 或 CLI 录入（M1） |
| **凭据不落地** | `assertSecretFree()` 在**写路径上**拦截：键名按"元数据白名单 + 后缀拒绝"判定，值里出现 PEM 私钥也拦。**这个判定是单一实现**，脱敏模块共用它，避免两套规则漂移 |
| **统一脱敏** | 落在**两个必经关口**：审计写入前（所以哈希链覆盖的是脱敏后内容 —— 审计要能证明"发生过什么"，但不能成为秘密的第二个副本）、以及所有工具的统一出口（远端回显不会把凭据带进模型上下文） |
| **fail-closed** | 审批服务不可用 → 拒绝执行；`exec.agent` 缺失 → 拒绝；计划无法验证新鲜 → 拒绝；动作参数未接线 → 阻断；R3 的复述机制未实现 → **阻断**（而不是记一笔"我跳过了"然后继续） |
| **动作目录是安全边界** | 加载器**拒绝未知字段**。理由：把 `risk` 拼错成 `Risk` 会让动作以默认 R1 运行 —— 本该 R3 的动作被静默降级。宁可启动失败 |
| **计划会过期** | 环境变了就不能沿用旧批准执行（TOCTOU）。审批前与执行前各校验一次状态指纹 + 有效期 |
| **危险动作** | 含内核升级 / 需重启自动升为 R2；R3 要求复述主机名 |

---

## 8. 开发与验证

```powershell
# 全套检查
npm run check

# 单项
npm run test            # 单元测试（174 项：core 132 + transport 9 + plugin-host 33）
npm run check:plugin    # 插件契约与行为（会用 DSH 自己的 schema 校验器验子集）
npm run check:faults    # 故障推演 / 回归（21 个探测点）
npm run check:ssh       # SSH 端到端（真实 ssh2 服务端，27 项）
npm run check:archive   # 归档（含 PowerShell 外部解压交叉验证，12 项）
npm run check:docs      # 文档里提到的项目内路径是否真实存在
npm run check:doctor    # 环境预检
npm run check:agent     # 协从端脚本（自动定位 bash，Windows 上无需改 PATH）

# 开发辅助
npm run doctor          # 环境预检（同上；排查"DSH 起不来"先跑它）
npm run cred            # 凭据录入（交互式、不回显）
node tools/lib/dsh-runtime.mjs   # 直接运行可打印 DSH 运行时依赖的探测结果
```

> **关于 `yaml` 与 `@deepseek-ai/dsh-tools`**：项目**不把它们列为依赖**，而是用
> `tools/lib/dsh-runtime.mjs` 从 DSH 安装目录**可移植地探测**（`@deepseek-ai/dsh-tools` 未发布到 npm；
> `yaml` 若独立安装就可能与 DSH 实际使用的版本漂移，而"我这边能解析、DSH 那边起不来"正是最糟的失败模式）。
> 探测不到时可用 `DSH_RUNTIME_ROOT=<含 node_modules/@deepseek-ai/dsh 的目录>` 显式指定。

### 8.1 发布流程（GitHub + Gitee 同步）

发布脚本在 `tools/release/`，令牌从 DSH 凭据库按需读取（`GITHUB_TOKEN` / `GITEE_TOKEN`）：

```powershell
node tools/release/verify-tokens.mjs        # 自检：令牌是否可用（只打印账号名，绝不打印令牌）
node tools/release/diagnose-github-push.mjs # 诊断：DNS / 端口连通性 / SSH 认证 / 该走哪条通道
node tools/release/publish.mjs              # 预演：查远端状态，不改动
node tools/release/publish.mjs --apply      # 真正发布：建仓（若无）→ 推 main + tags → 发 release
node tools/release/publish.mjs --apply --move-tag   # 把 tag 强制挪到当前提交（仅用于发布物有缺陷时）
node tools/release/publish.mjs --apply --skip-push  # 只补发 release（代码已用 API 通道推上去时）
node tools/release/verify-published.mjs v0.3.0      # 从两个平台的 API 核对仓库/tag/release/提交
```

**推送通道是自动选的**（本机踩过真实的连通性问题，见下表）：

| 顺序 | 通道 | 什么时候用 |
|---|---|---|
| 1 | **SSH**（`git@github.com:…`） | `ssh -T git@github.com` 认证通过时**首选** —— 本机 `github.com:443` 会被干扰，而 `:22` 正常 |
| 2 | **HTTPS**（可配 `VMPROBE_GIT_PROXY`） | SSH 不可用、但 HTTPS 能过 TLS 时 |
| 3 | **REST API**（`push-via-api.mjs`） | 前两条都不通、只剩 `api.github.com` 可用时（Git Data API 逐块复刻提交） |

> ⚠️ **本机实测结论**（`diagnose-github-push.mjs` 可复现）：`github.com:443` **TCP 连得上但 TLS 被重置**
> （`curl` 报 `Empty reply from server`），所以 `git push` 走 HTTPS 必然失败；同一网段的
> `api.github.com` / `codeload.github.com` / `ssh.github.com` 都正常，`github.com:22` 也正常。
> **不是 DNS 污染，也不是本机配置问题**（hosts 无条目、无系统代理、DNS 解析正常），
> 而是针对该域名 443 端口的连接干扰。因此 GitHub 一律走 SSH；首次使用需把公钥登记到 GitHub
> （`diagnose-github-push.mjs` 会告诉你缺哪一步，令牌有 `admin:public_key` 时可自动登记）。

四条刻意的设计（都是踩过之后加的）：

| 设计 | 原因 |
|---|---|
| **令牌绝不落盘、不进命令行参数** | 推送时写一个**临时**凭据文件交给 git（`credential.helper=store --file=…`），推完立即删除；远端地址始终不含令牌，`.git/config` 里也不会留下 |
| **临时凭据路径必须用正斜杠** | git 的配置值里**反斜杠是转义符**：用 `C:\Users\…` 会被吃掉反斜杠变成相对路径，于是 git 把**明文令牌写进了仓库工作区**（实测发生，3 个文件，未被提交，已删除）。现在路径用 `/`，并断言落点 + 推送后扫描工作区，发现即删除并报错 |
| **双平台幂等 + 互不阻塞** | 重跑发布不能失败（GitHub 的"已存在"是 422、Gitee 是 400）；且一个平台不通不该让另一个也不发 |
| **API 调用带重试** | 首次发布就遇到 `HTTP/2 GOAWAY` 抖动；不写重试会留下"仓库建好、代码推上去、release 没发出来"的半成品状态 |

> ⚠️ 发布脚本会创建**公开**仓库。若想改成私有，在平台上改一次即可（脚本只在创建时决定可见性）。

已修复的 **45 项缺陷**（含 3 项只有真机验证才能发现、1 项在写代码时被自己拦住、1 项被"绿测试"掩盖）证据与修法见 `ISSUES.md`。

---

## 9. 二次开发

**请看 `DEVELOPMENT.md`** —— 本项目的二次开发手册，包含：

- **开发进度台账**：每个模块的状态与证据（单测 / 推演 / 真实 SSH）
- **已核实的 DSH 集成事实表**：工具 / 审批 / 渲染 / slot 的确切类型形状，以及 **17 条实测出来的坑**
  （裸路径不行、目录导入不行、`file:` 不刷新、`--help` 提前短路、容器注入顺序、
  重复 entry id 致命、bundles 与依赖必须成对、凭据写错整棵树失败、JSON Schema 子集、
  Windows/MSYS 路径分裂、`timeoutMs: null` 会让整棵树加载失败…）
- **6 个扩展 recipe**：新增动作 / 新增工具 / 接入传输层 / 新增客户端 UI / 调整审批策略 / 新增校验探测
- **测试与调试方法**：怎么加一个推演探测点、怎么用加载台账、临时实例纪律、四条测试纪律
- **二次开发硬约束**：fail-closed 清单、"不要谎报"原则、确定性要求、凭据纪律
- **已知限制与技术债**（13 项，含客户端 UI 受环境阻塞的实测证据）
- **路线图 M1–M5**：具体到文件与验收标准；M1/M2 已完成项逐条列出结果
- **单台 → 多台的演进路径**：明确指出当前为单台做了哪些简化

想快速上手改代码，最短路径是这三步：

1. `npm run check` 先跑绿（确认环境与基线）。
2. 读 `packages/catalog/actions/system.update.json` —— 它是"声明式动作"的完整范例
   （参数、发行版分流、`check` / `verify` / `dryRun` / `rollback` 都在里面）。
3. **加一个新动作不需要改插件代码**：在 `packages/catalog/actions/` 放一个 JSON，
   跑 `npm run check:faults` 与 `npm run check:ssh` 验证加载与执行。
   只有当你要动"传输 / 审批 / 存储 / 渲染"时才需要改 `packages/**/src`。

---

## 10. 文档索引

| 文档 | 用途 |
|---|---|
| `README.md` | 本文：安装、使用、排查、安全 |
| `DEVELOPMENT.md` | **二次开发手册**：进度、扩展指南、路线图 |
| `DESIGN.md` | 架构设计与设计决策 D1–D8（含被否方案与理由） |
| `ISSUES.md` | 缺陷台账：三轮推演的 27 项证据与修法 |
| `docs/M0-验证报告.md` | 历史记录：DSH API 核实过程与对设计稿的 4 处修正 |
