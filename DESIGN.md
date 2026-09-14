# VMProbe —— 虚拟机探针系统 架构设计

> 目标系统：任意 Linux 发行版（协从端） · 主控端：Windows / Linux（DeepSeek Harness 插件）
> 文档版本：v0.2（M0 验证后修订） · 状态：**M0 骨架已落地**
>
> **v0.2 修订说明**：M0 阶段核对了 DSH 的实际类型声明，发现并修正了 v0.1 中 4 处与真实 API 不符的设计
> （`ToolDefinition.output` 为必填、`ApprovalRequest` 字段集、`apply()` 同步性、`dsh-schedule` 未组合）。
> 逐条证据与实测结果见 `M0-验证报告.md`。

---

## 0. 一句话概括

VMProbe 是一套「**主控端（DSH 插件）＋ 协从端（Linux 单文件探针）**」的虚拟机运维系统：主控端以内嵌 SSH 传输层长期保活连接，把用户/模型发出的意图翻译成**带风险分级、可预演、可验证、可回滚的结构化动作**，经 DSH 审批 seam 确认后下发到协从端执行，全过程双端留痕、可整体导出迁移。

---

## 1. 目标与非目标

### 1.1 目标

| 编号 | 目标 | 验收方式 |
|---|---|---|
| G1 | 主控端以对话形式（DSH 界面）完成虚拟机运维，无需手工敲 ssh | 对话「查看虚拟机状态」能返回真实 facts |
| G2 | 首次用密码接入，随后可一键切换为免密登录，且**切换过程不会锁死** | 切换后旧连接被主动切断，新连接免密成功；人为破坏验证步骤时旧连接仍可用 |
| G3 | 覆盖「任意 Linux 发行版」，同一逻辑动作按发行版自动分流 | apt / dnf / pacman / zypper / apk 至少 5 系实测通过 |
| G4 | harness 运行期间 SSH 始终保活，命令到达延迟为「复用连接」级 | 空闲 30 分钟后首条命令 < 200ms（不含远端执行） |
| G5 | **每条命令下发前经 harness 确认**，确认内容人类可读 | 审批记录含动作标题、风险级、解析后的真实 argv |
| G6 | 提供运行日志与命令使用日志，双端可交叉核对 | 任一次执行能用 traceId 在两端日志中定位 |
| G7 | 一键导出/导入，跨 Windows↔Linux 迁移目标与策略 | 在 Windows 导出，在 Linux 导入后功能等价 |

### 1.2 非目标（v1 明确不做）

- 不做 Web 端多用户/多租户与权限体系（单用户本机工具）。
- 不做对 Windows / macOS **被控端**的支持（协从端仅 Linux）。
- 不做 Ansible/Salt 式的批量配置管理 DSL（只做「探针 + 动作」，不做编排引擎）。
- 不内置密码/密钥的云端同步；凭据不随归档迁移（见 §11.4）。
- 不做 GUI 独立安装包；主控端 UI 完全寄生于 DSH Web 界面。

---

## 2. 总体架构

```
┌─────────────────────────── 主控端（Windows / Linux）───────────────────────────┐
│                                                                               │
│  DeepSeek Harness 进程                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ ① DSH Host 插件  plugin-host                                            │  │
│  │    · ctx.tools      注册 vmprobe_* 工具（模型可见的唯一入口）             │  │
│  │    · ctx.approval   逐条命令审批（fail-closed）                          │  │
│  │    · ctx.storage    目标/策略/归档元数据持久化                            │  │
│  │    · ctx.jobs       长任务（系统更新）后台运行 + 输出流                    │  │
│  │    · ctx.timer      保活心跳 + 定时报告（不依赖会话存活）                  │  │
│  │    · ctx.schedule   （可选）会话内定时提醒 → 新回合报告                    │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ ② DSH Client 插件  plugin-client（浏览器侧）                             │  │
│  │    · conversation.session.header.actions → 连接状态徽标 + 目标列表        │  │
│  │    · 设置页：目标管理 / 风险策略 / 导入导出                                │  │
│  │    · 独立 locale 命名空间；工具结果定制渲染（plan 卡片、diff 卡片）        │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ ③ 核心引擎  core（纯逻辑，零 DSH 依赖，可单测）                           │  │
│  │    连接状态机 │ 动作目录 │ 策略引擎 │ 运行记录 │ 审计链 │ 归档编解码       │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ ④ 传输层  transport（统一接口，双后端）                                   │  │
│  │    embedded: ssh2（纯 JS，跨平台一致，支持密码认证）  ← 默认              │  │
│  │    native  : OpenSSH + ControlMaster（复用用户 ~/.ssh/config、agent）     │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ ⑤ 独立 CLI / TUI  cli（不装 DSH 也能用；DSH 故障时的救援通道）             │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│                                   │                                           │
└───────────────────────────────────┼───────────────────────────────────────────┘
                                    │  SSH（单条复用连接 / ControlMaster 多路复用）
                                    │  控制平面：动作目录调用，JSON 结构化
                                    │  数据平面：sftp 通道传文件（互不阻塞）
┌───────────────────────────────────┼───────────────────────────────────────────┐
│                          被控虚拟机（任意 Linux 发行版）                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ 协从端  vmprobe agent                                                   │  │
│  │  · 能力探测 facts：发行版/内核/arch/init/包管理器/虚拟化/网络/磁盘         │  │
│  │  · 动作执行器：按发行版分流、幂等、可 dry-run、超时与资源限制              │  │
│  │  · 本地审计日志：/var/log/vmprobe/*.jsonl（哈希链 + logrotate）           │  │
│  │  · 可选守护进程 --daemon：unix socket，任务流式输出 + 本地定时报告         │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 两条独立数据平面

设计上刻意把「控制」与「数据」分开，避免大文件传输阻塞命令通道：

- **控制平面**：动作调用、心跳、状态回报。请求/响应均为结构化 JSON（`vmprobe/1` 协议），单条消息有界（>256KiB 自动落盘并返回引用）。
- **数据平面**：文件上传/下载走 SSH 的 SFTP 子系统（`ssh2` 的 `sftp()` / native 的 `sftp`），与 exec 通道并发，互不阻塞。

---

## 3. 关键设计决策（含被否方案）

> 这几条是整个设计的支点，请重点评审。

### D1 —— 接口不是「shell 字符串」，而是「动作目录 + 风险分级」

**决策**：协从端对外暴露的是**声明式动作目录（Action Catalog）**，不是裸 shell。分三档执行能力：

| 档 | 名称 | 形态 | 默认 | 审批 |
|---|---|---|---|---|
| T1 | **动作 Action** | 目录定义、参数有类型、按发行版分流、幂等、可 dry-run | ✅ 主路径 | 按风险级 |
| T2 | **受限命令 Command** | 白名单可执行文件 + argv 数组，**不经 shell** | 需按目标开启 | 每次 R1+ |
| T3 | **原始 Shell** | 传给 `sh -c`，任意字符串 | ❌ 默认关闭 | 每次 + 强制理由 + 建议快照 |

**理由**：

1. **审批才有意义**。审批弹窗要给人看的是「将重启 nginx 服务，预计中断 5 秒」，而不是 `systemctl restart nginx && sleep 2 && curl -sf localhost:80`。只有 T1 能提供标题、摘要、影响面。
2. **「任意发行版」才成立**。同一个 `system.update`，在 Debian 是 `apt-get dist-upgrade`、RHEL 是 `dnf upgrade`、Arch 是 `pacman -Syu`、Alpine 是 `apk upgrade`。分流逻辑放在目录里由协从端按 facts 解析，主控端与模型都不需要知道发行版细节。
3. **可审计**。日志里记的是 `action=system.update params={securityOnly:true}` 和**解析后的真实 argv**，而不是一段含义模糊的字符串。
4. **可验证/可回滚**。只有声明式动作能带 `check / apply / verify / rollback` 四段，才能做到「更新完再查一遍确认真的更新了」。

**被否方案**：直接 `vmprobe_exec(command: string)` 单一工具。实现最快、最灵活，但它把「安全边界」和「跨发行版适配」全部外包给了模型——等于让 LLM 每次现场生成 root shell 命令，即不可审计也不可回滚，且模型幻觉一条 `rm -rf` 就结束了。它只保留为 T3 逃生舱。

### D2 —— 传输层用 `ssh2` 作为默认后端（而非 shell 调用 `ssh.exe`）

**决策**：抽象 `SshTransport` 接口，双后端；**默认 `embedded`（ssh2）**，`native`（OpenSSH + ControlMaster）作为可选项。

**理由（这是 Windows 主控端的关键约束）**：

- Windows 的 `ssh.exe` **无法从 stdin/env 接收密码**，也没有 `sshpass` 等价物。而需求第 1 步就是「使用密码以 ssh 协议登录」——用 `ssh.exe` 这条路在 Windows 上根本走不通（除非引入 `plink.exe`，多一个外部依赖）。
- `ssh2` 是纯 JS 实现（可选原生加速，无原生也能跑），**Windows / Linux 行为完全一致**，天然支持密码认证、单连接多通道复用、keepalive、SFTP、端口转发。
- **保活是「内建」而非「配置」**：一条长连接 + N 个 exec channel 本身就是保活（G4）。不需要 ControlMaster 那套 socket 文件（在 Windows 上 `ControlPath` 的路径/权限问题很多）。
- **不存在「主控端未装 OpenSSH」的失败态**。

**`native` 后端保留给**：用户已有 `~/.ssh/config`、`ProxyJump` 跳板机、硬件 key（FIDO）、ssh-agent 里已有凭据的场景。两后端实现同一接口，目标粒度可选。

**被否方案**：`ssh.exe` + `ControlMaster` 作为唯一后端 —— 保活语义最「正统」，但密码引导无解、Windows 路径坑多。

### D3 —— 「配置免密」设计为**事务**，而不是「配好就切」

需求原文是「自动配置 ssh 密钥，然后主动切断链接再以免密方式登录一次」。字面实现有个致命隐患：**如果新配的密钥其实不可用（权限位错、`sshd_config` 禁用了 pubkey、SELinux 上下文、家目录加密、`AllowUsers` 不含该用户），切断旧连接后你将永久失去该虚拟机**。

**决策**：认证切换是原子事务，顺序为：

```
生成专用密钥 → 写入 authorized_keys（先备份） → **另开一条连接用密钥验证成功**
   → 验证成功：才切断旧密码连接、抹除内存中的密码、切换 authRef
   → 验证失败：保留旧连接、回滚 authorized_keys、报告失败原因（绝不切断）
```

核心不变式：**任何时刻至少存在一条可用的连接路径**。这是整个系统最重要的一条安全属性。

**撤销（disable）是同一个事务的镜像，且必须同样保守**：先验证**口令路径**确实可用，再移除
`authorized_keys` 里的公钥行 → 失败则保持原样。否则会造出一个"密钥删了、口令也不对"的目标。

**踩过的坑（N8）**：切换认证方式时 `switchTargetAuth` 会把目标上的 `authRef` **覆盖**成新 ref，
于是启用免密之后**口令 ref 就丢了** —— 撤销时"先验证口令路径"这一步无从下手，只能拒绝执行。
行为上是 fail-closed（拒绝了，没干错事），但**功能实际不可用**。修法：切换时记住
`previousAuthRef`（**仅当原认证方式不是密钥时才记**，避免自我引用），撤销时回退使用它。
**教训**：一旦把"当前认证方式"做成单一字段，就必须同时记住"上一条可用路径" ——
因为本设计的不变式要求的不是"当前路径可用"，而是"**至少一条**路径可用"。

**被否方案**：按字面「配完就切」。第一次遇到 `sshd_config` 里 `PubkeyAuthentication no` 就会锁死虚拟机，用户只能走 VNC/控制台救回来。

### D4 —— 密码绝不进入模型上下文与会话日志

**决策**：目标密码/密钥口令通过以下路径之一进入，**不经过对话文本**：

1. Client 插件的**掩码输入框**（设置页添加目标）；
2. 独立 CLI：`vmprobe auth set <target>`（交互式无回显读取）；
3. 环境变量注入（CI 场景）。

DSH 工具 `vmprobe_connect` 若发现该目标无凭据，返回 `{ needsSecret: true, prompt: "…" }`，由 Client 插件弹出输入框，凭据写入凭据库后再续跑。

**理由**：DSH 会话是**持久化且会被完整重放/导出的**（`~/.dsh/sessions/`）。用户在聊天框里打一次密码，这串密码就永久留在了会话存档里，还会被后续每一轮上下文注入。这跟「凭据不进日志」的目标直接冲突。

**落地位置**：优先复用 DSH 凭据存储（`~/.dsh/.credentials.yaml`，DSH 自己读取）；更严格模式用 scrypt + AES-GCM 加密的本地 vault（见 §9.4）。

**被否方案**：让用户直接在对话里说「密码是 xxx」。方便，但等于把密码写进明文的会话日志，不可接受。

### D5 —— 审批分级，而非「每条命令都弹窗」

需求是「每发出一道命令都需要 harness 确认」。**字面执行会毁掉可用性**：一次 `probe.facts` 探针、一次心跳、一次状态查询都弹窗，一轮「查看虚拟机状态」就要点 5～8 次确认，用户必然开始无脑点同意——**审批反而失效**。

**决策**：按风险级分流，且**全部留痕**（无论是否弹窗）：

| 级 | 含义 | 审批行为 |
|---|---|---|
| R0 | 只读、无副作用（探针、状态、日志读取） | 自动放行，记审计 |
| R1 | 可逆变更（装包、改配置、写文件、启停服务） | **每次弹窗**（显示标题/影响面/argv） |
| R2 | 破坏性或影响面大（含内核升级、需重启） | 每次弹窗 + 影响面警示 + 建议快照 |
| R3 | 特权且不可逆（重启、删数据、改 sshd 配置、切认证） | 每次弹窗 + **要求用户复述目标主机名**方可确认 |

**注**：DSH 的审批 seam（`ctx.approval.request`）授予的是 **`allowed-once`——仅本次**，无法通过它做「记住 30 天」。因此免打扰只能由插件层自建「策略授权」（scoped grant，带 TTL）。**R2/R3 永不授权**，因为它恰恰是最需要人看的两级。

> ✅ **已拍板（2026-09-14）**：用户选择 **R0/R1 免弹但留痕，仅 R2/R3 弹窗**。
> 代码已落地于 `packages/core/src/risk.js` 的 `DEFAULT_POLICY.autoAllowUpTo = 'R1'`，
> 并有单测锁定（`packages/core/test/risk.test.js`）。
> 若日后要改回「一条不落全弹窗」，只需把 `autoAllowUpTo` 降到 `R0` —— 策略是数据，不是散落的 if。
>
> ⚠️ **M2 修正（技术债 #1）**：上面这句话当时**并不成立** —— `DEFAULT_POLICY.autoAllowUpTo` 只是被写上，
> `decideApproval()` 实际只用 `alwaysAskFrom` 判定，所以在配置里改它**毫无效果**；
> 更糟的是插件配置里那个键同样透传不进去。现在两处都真的接线了：
> core 的判定同时看 `autoAllowUpTo` 与 `alwaysAskFrom`（默认值下行为完全一致，是纯粹的"让文档成真"），
> 插件把配置里的策略透传给 `buildPlan({ policy })`，并在启动时把**实际生效的策略**记入审计
> （`config.effective`）—— 放宽免审批范围属于安全相关改动，必须可追溯。
>
> ⚠️ **M0 补充的约束**：`ctx.approval.request` **要求当前有打开的回合（open turn）**，
> 空闲时发起会被拒绝。这意味着**定时器驱动的任务无法申请审批** ——
> 所以定时任务（§6.4）只能做 R0/R1，R2/R3 必须经由对话回合发起。

### D6 —— 协从端「CLI 优先，守护进程可选」

**决策**：协从端核心是**无状态单文件 CLI**，每次由主控端经 SSH exec 调用（`vmprobe action run <id> --params-json ...`）。`--daemon` 是可选升级形态。

| | 无守护（默认） | 守护进程（可选） |
|---|---|---|
| 进程模型 | 每命令一进程，执行完退出 | systemd 常驻，unix socket |
| 安装/卸载 | 极简，删文件即净 | 需 unit + 生命周期管理 |
| 攻击面 | 无常驻监听 | 仅 unix socket（不监听 TCP） |
| 流式输出 | SSH 通道天然支持 | 支持，且断连后任务可继续 |
| 控制器离线时 | 什么都不能做 | 本地定时报告 + 任务续跑 |
| 适用 | v1 默认 | 需要「控制器关机也每天报告」时 |

**理由**：先做无状态版本，能用一条 SSH 连接解决 90% 需求，且**卸载干净**（探针类工具最忌讳在被控机上留一堆常驻物）。守护进程只在「本地定时」和「断连续跑」两个真实需求出现时再引入。

### D7 —— 差分两阶段失败：`check` 先于 `apply`

**决策**：所有 T1 动作必须实现 `check`（探测当前状态）。执行流程为：

```
check（只读）→ 生成 plan（将做什么 / 已是目标态则直接返回 no-op）→ 审批 → apply → verify
```

**理由**：
- **幂等性由 check 保证**，而不是靠命令自身幂等（`authorized_keys` 重复追加是经典事故）。
- 用户审批时看到的是**差分**（「3 项待更新，含内核 → 需重启」），而非「我要跑 apt upgrade」。
- 省事：`system.update` 在已最新的机器上直接返回 `no-op`，不打扰、不弹窗。

### D7.5 —— 执行之后必须**判定**，而不是"命令返回 0 就算成功"（M2）

**决策**：动作可以声明 `verify`，它在 apply 之后**真的再跑一次探测**并给出三态结论：

```jsonc
"verify": { "probe": "pkg.upgradable", "expect": { "count": 0 }, "maxWaitMs": 5000 }
```

| `verify.satisfied` | 含义 | 何时出现 |
|---|---|---|
| `true` | 达到目标态 | 探测结果里 `expect` 列出的字段全部相符 |
| `false` | **未**达到目标态 | 有字段不符；或 `expect` 列了而探测结果里没有该字段 |
| `null` | **未判定** | 没声明 `expect`；探测未实现；预演（dryRun）；无传输层 |

四条刻意的设计：

1. **"命令成功"与"达到目标态"分开报**。`apt-get dist-upgrade` 返回 0，但可能仍有被 hold 的包 ——
   把两件事合并成一个 `ok`，就是在制造"看起来成功了"的假象。
2. **`null` 不是 `true`**。没声明 `expect`、探测没实现、预演没产生变更 —— 这些都是"无法判定"，
   而不是"通过"。**字段永远存在且取三态之一**，缺字段会诱使调用方写出 `if (verify.satisfied)` 的错判。
3. **`expect` 只声明"应达到什么"，不写判定代码**。规则是"逐字段严格相等（数组按序）"，
   由宿主的加载器校验形状（标量或标量数组，拒绝深层结构）——
   让"是否达标"一目了然，而不是藏在某个表达式里。
4. **预演不校验目标态**，并**说明原因**（`skipped: true, reason: 'dryRun…'`）：
   预演什么都没改，去校验目标态只会得出误导性的"未达标"。

`maxWaitMs` 处理的是真实世界的延迟：`dist-upgrade` 返回后 `apt list --upgradable` 可能短暂仍列出被 hold 的包。
等一小会儿再判定，比"立刻宣布失败"更接近事实 —— 但**等到超时也绝不编造成功**。

### D7.6 —— 运行输出落盘，审计只留**引用与摘要**（M2）

**问题**：把 `apt-get` 的几千行输出塞进审计事件，会让审计文件被单次输出撑爆（轮转阈值 8 MiB 一次就满），
并且稀释哈希链的价值 —— 链该记"发生了什么"，不是"命令打印了什么"。

**决策**：每次执行写一份 `runs/<runId>.log`（人类可读：计划摘要、逐条命令、exit、stdout/stderr、校验结论），
审计只记 `{ runId, runPath, runSha256, runBytes, exit, verify }`。四条配套纪律：

| 纪律 | 理由 |
|---|---|
| **写盘前过同一套 redactor** | 输出可能含密码回显/token；两套脱敏规则必然漂移（I8 的教训） |
| **runId 必须校验形状**（`r_…`，无分隔符与点） | 它会变成**文件名**；不校验就是在日志目录里开路径穿越（F6 同类） |
| **超限截断并标注** | 宁可写一行 `[已截断]`，也不要悄悄丢尾巴让人以为"输出就这么长" |
| **失败/取消也要落盘** | 失败更需要事后复盘；"没有文件"不该是无法区分「没跑」与「跑了但挂了」的状态 |

事后取证：`engine.verifyRunSeal({ runId, sha256 })` 用审计里的摘要核对文件是否被改动过。

### D7.7 —— 取消是**可预期结局**，不是失败（M2）

**决策**：`exec.signal` 一路贯通到 SSH 通道，中断时与超时走**同一条**清理路径：
先给通道发 TERM（让远端进程真的收到信号），3 秒后硬关通道。三处刻意设计：

1. **取消与失败分开记**：`action.cancelled` ≠ `action.run.failed`。取消要留痕（否则"任务去哪了"无人能答），
   但不该被当成故障去告警、也不该污染失败率。
2. **取消关的是通道，不是连接**：中断后连接仍然可用（真实验证：取消后立刻再执行一条命令成功）。
3. **工具可以声明 `timeoutMs` 了** —— 因为取消真的贯通了。DSH 的契约是：声明 `timeoutMs` 即断言
   "该工具把 `exec.signal` 转发给协作式实现"。以前不声明是**刻意的诚实**（F4：声明了却在跑，
   会让 DSH 以为已中止）；现在声明，是因为它成了真话。额度取自目录里最长的动作预算再加余量，
   属**兜底**（逐条保护在更内层：连接、单命令、探测各自有超时）。

### D8 —— plan 是一次**会过期**的承诺：状态指纹 + 有效期（TOCTOU 防护）

**决策**：plan 不仅记录"要做什么"，还记录"**做决定时环境长什么样**"：

| plan 字段 | 作用 |
|---|---|
| `stateFingerprint` | 对 check 结果中**影响决策的字段**求 sha256（排除 `note`/`probedAt` 等易变字段） |
| `checkedAt` / `expiresAt` / `ttlMs` | 时间维度的有效期（默认 5 分钟） |

校验点有**两处**，且都在不可逆动作之前：

```
plan → 能力前置检查 → ①新鲜度校验 → 审批 → ②新鲜度复校（执行前）→ apply
```

**为什么必须有这条**（这是 TOCTOU，不是洁癖）：
用户批准的是「12 个包待更新，含内核，需重启」。如果这几分钟内另一个管理员已经更新完，
那么此时执行的是**一次他从未批准过的操作**（可能是一次不必要的重启）。
「计划里写着 12」不足以约束执行 —— 执行前必须能**验证环境还是那个环境**。

**为什么把校验放在审批之前**：不拿一个已经失效的计划去占用用户的注意力。
这与 D5 的"不为做不到的事浪费审批"是同一条纪律的延伸。

**两条辅助决定**：

1. **指纹只覆盖影响决策的字段**，且用**排除法**（新增字段默认纳入）。
   取舍：新增字段被纳入 → "环境变了"更容易被发现（宁可多要求一次重新计划）；
   代价是生产者若往 check 结果里塞时间戳就会"永远过期"，故约定**易变信息放 `note`**。
2. **拿不到指纹时（未实际探测）也判为不新鲜**，不做"控制器侧动作就放行"的例外。
   fail-closed 一致到底：宁可多一次重新计划，也不静默按旧计划执行。

### D9 —— 协从端**零安装**：脚本经 SSH stdin 投递

**决策**：首次接触**不往被控机落任何文件**。主控端把 `agent/bootstrap.sh` 经 SSH 的 stdin 交给远端 `sh` 执行：

```
ssh <target>  "sh -s -- --check"   ← stdin = bootstrap.sh 的内容
```

**理由**：
- 只要求远端有一个 **POSIX sh**（不必有 curl/wget/python/node，也不必先跑一次安装器）。
  于是"添加一台服务器 → 立刻看到画像"是一条直线，没有中间步骤。
- **零残留**：探针类工具最忌讳在被控机留一堆常驻物；不装就没有卸载问题。
- 不用 SFTP：exec 通道本就是 8 位透明的，少一个子系统依赖。

**Go 静态二进制的定位被下调**：它不再是"能不能用"的前提，而是**性能与长期驻留的优化**
（更快启动、守护进程、本地定时），属 M4。原需求"安装一个协从端"在语义上仍成立 ——
只是协从端暂以**脚本形态投递**，而不是落地为二进制。

### D10 —— 文件投递走 **exec + stdin**，不用 SFTP

**决策**：`pushFile` 用 `sh -c 'mkdir -p "$(dirname "$1")" && cat > "$1" && chmod M -- "$1"' sh <path>`，
内容写进 stdin。

**理由**：SSH 通道对二进制是透明的；少一个子系统依赖；**测试台能真实覆盖这条路径**（不必实现 SFTP 服务端）。
代价是大文件占满一条通道且无断点续传 —— 那属于将来的大文件传输，届时再引入 SFTP。

### D11 —— 参数接线**由 argv 用法推导**，而不是作者声明

**决策**：动作在 argv 里就地声明参数用法：`{"$param":"x"}` / `{"$param":"x","prefix":"--p="}`（值替换，
数组展开成多个参数）、`{"$when":"x","argv":[…]}`（条件参数）、`"{{x}}"`（字符串内插）、
分支级 `dryRun`（为真时替换 cmd 并跳过 pre）。

`resolveCommands()` 返回 **`consumedParams`**（argv 里真正引用到的参数名），
`buildPlan` 用它判定"传了但没人消费"的参数并 **fail-closed 阻断**。

**为什么不用 `wiredParams` 这种静态声明**：声明与实现必然漂移，而漂移的后果正是最危险的形态 ——
"以为只装安全更新、实际全量升级"（缺陷 F2）。改成推导式后，**没被 argv 引用的参数一定被拦下**，
作者无从伪装。旧字段保留但已废弃，加载器发现"声明了却没被引用"会直接报错。

**一个自然副产品**：参数支持变成**按发行版区分**。`securityOnly` 只在 dnf/zypper 分支被引用，
所以在 Debian 上传它会被阻断并说明原因 —— 这比"假装支持"诚实得多。

**我差点违反自己的规则**：给 Debian 分支写过 `{"$when":"securityOnly","argv":[]}`，
那会让它"看起来接线了"却什么也不做，正是 F2 的形态；自审时删掉了（`ISSUES.md` §10.2）。

### D12 —— 宿主的 JSON Schema 子集是硬约束

**必须遵守，写在这里免得再踩**：DSH 只接受 **JSON Schema 子集** —— 单个标量 `type`、
`properties`/`required`/`additionalProperties`、`items`、标量 `enum`/`const`、
**恰好一个分支的 `oneOf`**，以及只有注解的 schema（表示不受约束）。

**不支持 `type: ['string','null']`**。踩过一次：真机启动直接失败、**整棵插件树加载不出来**
（`unsupported JSON schema: ... type must be a single type string`）。
可空字段的正确写法是 `oneOf: [{type:'object'},{type:'null'}]`。

**防复发**：契约检查直接调用宿主的 `assertSupportedJsonSchema` / `assertObjectJsonSchema` /
`validateJsonSchemaValue` —— 规则永远与宿主一致，不需要我们维护一份清单。

### D13 —— 心跳是**观测**，不是**保活**；且观测必须分层

保活与观测是两件不同的事，早期设计把它们混在一条 `probe.ping` 动作里，实现时拆开了：

| | 手段 | 职责 |
|---|---|---|
| **保活** | `ssh2` 的 `keepaliveInterval: 15_000` / `keepaliveCountMax: 4`（+ TCP keepalive） | 让链路**不要断**。它不产生任何业务事实 |
| **观测** | 传输层的 `heartbeat(targetId)`：在**已有会话**上跑 `echo vmprobe-hb`，60s 一次、5s 超时 | 回答"现在**还连着**吗、延迟多少"——把健康度变成**可查询的事实** |

**三条刻意设计（是契约，不是实现细节）**：

1. **绝不主动建立连接。** 没有会话就如实报 `no-session`。若心跳顺手把连接拉起来，
   它就会**掩盖**"其实早就断了"这一事实 —— 那正好毁掉心跳存在的理由。
2. **失败即把会话标成 `detached`**（含非零退出、超时、通道错误）。宁可"看起来断了但其实还能连"，
   也绝不留下"看起来还连着但其实早断了"的假象：前者下次操作会重连成功，后者会让人基于假状态做决定。
3. **分层**：transport 只报**事实**（`{ok, reason, latencyMs, error}`），
   **引擎层**负责统计与记忆（`consecutiveFailures`、`lastFailure`、审计）。

**第 3 条是踩出来的**：曾把 `consecutiveFailures` 期望在 transport 层返回 —— 那是统计职责而非观测职责。
更实际的问题是**信息丢失**：失败时 transport 已把会话拆成 `detached`，于是**下一次**心跳只能报
`no-session`，"它为什么掉了"就再也答不上来。因此引擎必须**单独记住最近一次真实失败**
（原因/错误文本/时间），恢复时清空 —— `undefined` 不等于"没发生过"。

**审计纪律**：心跳 60s 一次，全记会淹掉审计链。只在**状态变化**时记：
失败记第 1 次与每 10 次，成功只记"首次"与"从失败恢复"。
（踩过一次：判据写成 `consecutiveFailures % 10 === 0`，而**成功时它恒为 0、`0 % 10 === 0` 恒真**
→ 每次成功都写一条，"不淹没日志"完全失效。）

**与 `probe.ping` 的关系**：`probe.ping` 作为**动作**仍然保留（R0、可在 plan 里出现、
可返回 load/uptime 等业务信息）；心跳走传输层直连，**不经过动作目录** ——
否则"观测连接"就需要先"通过目录构建 plan"，逻辑上倒置，且心跳会在目录出错时一起失效。

---

## 4. 连接与保活模型

### 4.1 连接状态机

```
        ┌──────────┐
        │ detached │◄──────────────── 应用退出 / 显式 disconnect
        └────┬─────┘
             │ connect(authRef)
        ┌────▼─────────┐   主机指纹不符 → 拒绝（除非显式批准新指纹）
        │ verifying    ├──────────────────────────────►┌────────┐
        │ host key     │                               │faulted │
        └────┬─────────┘   认证失败 → 记录失败原因     └───┬────┘
             │                                               ▲
        ┌────▼─────┐   网络抖动（自动重连，指数退避+抖动）    │
        │connected │◄────────────┐                          │
        └────┬─────┘             │                          │
             │ 空闲              │                          │
        ┌────▼─────┐  心跳失败（一次即够，见 D13）        │
        │  idle    ├───────────────────────────────────────┘
        │(keepalive│        ↑ 标记 detached ≠ faulted：
        │ 心跳中)  │          下次操作会正常重连，不锁死目标
        └────┬─────┘
             │ 动作执行
        ┌────▼─────┐
        │executing │  （可并发：动作串行，探针/状态可并行）
        └──────────┘
```

### 4.2 保活的具体手段（三选一叠加）

1. **连接复用（主力）**：`ssh2` 单条 `Client` 连接，所有命令走其上并发的 exec channel。连接存活期间**零握手开销**。
   - TCP keepalive：`socket.setKeepAlive(true, 30_000)`
   - SSH 层心跳：`keepaliveInterval: 15_000`、`keepaliveCountMax: 4`（实现于 `ssh2`）
2. **应用层心跳（观测用，已实现）**：传输层每 60s 在**已有会话**上跑 `echo vmprobe-hb`（`heartbeat()`），
   失败即把会话标 `detached`；`vmprobe_status` 展示延迟、连续失败次数与**最初失败原因**。
   - 作用不只是保活，更是**把连接健康度变成可查询的事实**（设计取舍见 D13）。
   - **不主动建立连接**：无会话就报 `no-session`，绝不为了"心跳成功"而偷偷重连。
   - 空闲退避到 300s 暂**未实现**（当前固定 60s，只探活跃会话，代价可忽略）。
3. **`native` 后端时**：`ControlMaster auto` + `ControlPersist 10m` + `ServerAliveInterval 30`，复用系统连接。

### 4.3 断连恢复

- **动作执行中断**：不等价于失败。远端可能已生效。恢复策略：重连后**先跑该动作的 `check`/`verify`**，据此判定 `applied` / `not-applied` / `unknown`，绝不盲目重放。
  - 长任务（系统更新）改用**幂等重入 + 日志续读**：远端把执行日志落到 `/var/log/vmprobe/runs/<runId>.log`，重连后用 `probe.run.log --tail` 续读。
- **守护进程模式**：命令走 unix socket，SSH 断连不影响远端任务；重连后按 runId 收割结果。

---

## 5. 协从端（vmprobe agent）设计

### 5.1 交付形态与引导

**双形态，按被控机条件自动选择**：

| 形态 | 构成 | 适用 |
|---|---|---|
| **A. 静态二进制（推荐）** | Go，`CGO_ENABLED=0` 静态链接，x86_64 / aarch64 / armv7 / riscv64 | 绝大多数发行版 |
| **B. 纯 POSIX sh 降级** | 单文件 shell，只实现 R0 探针 + 简单动作 | Alpine/busybox、只读根、无 exec 权限目录、无法落地二进制 |

**引导流程**（不假设远端有 python/node/git/curl）：

```
1. 本地读 /etc/os-release（通过 exec 通道，无需落地文件）
   → 得到 ID / ID_LIKE / VERSION_ID / 包管理器 / init 系统 / arch / libc
2. 按 arch+libc 选择二进制；尝试下载：
   优先：主控端经 **SFTP 通道直接推送**（不依赖远端 curl/wget/网络出口）  ← 关键
   兜底：远端 curl/wget 从配置的镜像拉取，并校验 sha256
3. 落地目录（按优先级探测可用性）：
   /usr/local/lib/vmprobe/        系统级（有 root）
   ~/.local/lib/vmprobe/          用户级
   /dev/shm/vmprobe-<rand>/       无写权限时的临时降级（明确告知不持久）
4. 生成 /usr/local/bin/vmprobe 软链 + 记录版本指纹
5. 可选：安装 systemd unit（守护模式）+ logrotate + sudoers 片段
6. 自检：vmprobe selfcheck --json → 版本/权限/可写目录/依赖
```

> **设计要点**：**二进制由主控端经 SFTP 推送**，而不是让被控机去外网下载。理由：内网/离线环境可用；不依赖被控机有外网出口；版本可控（不装最新，装主控端打包的那个版本）；可校验 sha256。

**卸载**：`vmprobe uninstall --purge` 逆序清理（unit → 软链 → 目录 → 日志，日志默认保留并可单独导出）。

### 5.2 能力探测（facts）

一次探测产生一份「虚拟机画像」，供动作分流与模型理解环境：

```jsonc
{
  "schema": "vmprobe/facts/1",
  "probedAt": "2026-09-14T10:00:00Z",
  "host": { "hostname": "vm-a", "machineId": "…", "bootId": "…" },
  "os":   { "id": "ubuntu", "idLike": ["debian"], "versionId": "26.04",
            "prettyName": "Ubuntu 26.04 LTS", "kernel": "6.14.0-11-generic",
            "arch": "x86_64", "libc": "glibc-2.41", "timezone": "Asia/Shanghai" },
  "init": { "system": "systemd", "version": "259", "userSession": true },
  "pkg":  { "managers": ["apt", "snap", "flatpak"], "default": "apt",
            "lockHeld": false, "upgradable": 12, "securityUpgradable": 3,
            "rebootRequired": false, "kernelUpgradePending": false },
  "virt": { "type": "kvm", "hypervisor": "KVM", "container": null },
  "hw":   { "cpu": { "model": "…", "cores": 4 }, "mem": { "totalMb": 8192, "availMb": 6100 },
            "disk": [ { "mount": "/", "fs": "ext4", "sizeGb": 40, "usedPct": 43,
                        "inodesUsedPct": 12, "snapshotCapable": "lvm" } ] },
  "net":  { "interfaces": [ { "name": "ens3", "ipv4": ["10.0.0.5/24"], "mac": "…" } ],
            "defaultGateway": "10.0.0.1", "dns": ["10.0.0.1"],
            "listeningTcp": [22, 80], "egressInternet": true },
  "ssh":  { "port": 22, "pubkeyAuth": true, "passwordAuth": true,
            "authorizedKeysPath": "/home/u/.ssh/authorized_keys",
            "configuredUser": "u", "sudoMode": "nopasswd-scoped" },
  "caps": { "root": true, "sudo": true, "systemd": true, "snapshot": null,
            "rebootAllowed": true, "selinux": "disabled", "apparmor": "enabled" },
  "probe": { "agentVersion": "0.1.0", "probeVersion": 1, "durationMs": 220 }
}
```

- **探测必须只读**（R0），且**不得**因为某项不存在而失败（每项独立捕获，缺失记 `null` + `errors[]`）。
- facts 落主控端 storage，模型只看到**摘要**（避免每轮灌入大 JSON）；完整 facts 按需 `vmprobe_facts get`。
- **敏感字段**：facts 可能含内网拓扑（IP、监听端口）。写入归档时按策略脱敏（§11.3）。

### 5.3 动作定义格式（目录条目）

内置动作以 YAML 声明，打包进二进制；用户可覆盖/新增（存于主控端，下发执行时携带）。

```yaml
id: system.update
version: 1
title:    { zh: 更新系统软件包, en: Update system packages }
summary:  刷新仓库元数据并升级全部可升级软件包
side:     agent                      # agent=远端执行 | controller=主控端本地执行
risk:     dynamic                    # 基线 R1；运行时若含内核/需重启 → 提升为 R2
params:
  securityOnly: { type: boolean, default: false, desc: 仅安装安全更新 }
  exclude:      { type: array<string>, default: [], desc: 锁定包名（glob，如 linux-*） }
  dryRun:       { type: boolean, default: false }
requires: { root: true, binaries: [], distros: ["debian","rhel","suse","arch","alpine"] }
idempotent: true
timeoutMs: 3600000
check:
  probe: pkg.upgradable            # → { count, sizeBytes, rebootRequired, kernelUpgradePending }
apply:
  debian:  { pre: [["apt-get","update"]],
             cmd: [["apt-get","-y","-o","Dpkg::Options::=--force-confold","dist-upgrade"]],
             env: { DEBIAN_FRONTEND: noninteractive } }
  rhel:    { cmd: [["dnf","-y","--refresh","upgrade"]] }
  suse:    { cmd: [["zypper","--non-interactive","update"]] }
  arch:    { cmd: [["pacman","-Syu","--noconfirm"]] }
  alpine:  { pre: [["apk","update"]], cmd: [["apk","upgrade"]] }
verify:
  probe: pkg.upgradable            # 期望 count==0（或 securityOnly 时无安全更新剩余）
  maxWaitMs: 5000
rollback:
  strategy: snapshot-if-available  # snapper/timeshift/LVM 存在则先快照，否则仅提示不可回滚
  snapshotBefore: true
notes:
  - 升级含内核时需重启才能生效，本动作不自动重启
  - 建议在执行前确认磁盘可回收空间 > 2GiB（check 会给出估算）
```

**控制器侧动作**（`side: controller`）—— 这类动作操作的是连接本身或本地数据，不经协从端：

| 动作 id | 风险 | 说明 |
|---|---|---|
| `target.add` / `target.remove` | R1 | 目标增删（凭据经安全通道另行录入） |
| `ssh.passwordless.enable` | R3 | 免密切换事务（§8.2） |
| `ssh.hostkey.rotate` | R3 | 主机密钥重新固定 |
| `agent.install` / `agent.upgrade` / `agent.uninstall` | R1/R2 | 协从端生命周期 |
| `archive.export` / `archive.import` | R1 | 归档（§11） |
| `policy.set` | R1 | 风险策略调整 |

### 5.4 执行器要点

- **不经 shell**：动作的 `cmd` 是 argv 数组，直接 `execve`。参数通过 argv 或环境变量传递，**绝不做字符串拼接**（消除注入面）。
- **环境净化**：固定最小 env（`PATH=/usr/sbin:/usr/bin:/sbin:/bin`、`LANG=C.UTF-8`、显式注入 `DEBIAN_FRONTEND` 等），不继承 SSH 传入的任意环境（阻断 `LD_PRELOAD`、`BASH_ENV` 类攻击）。
- **超时与取消**：超时 → `SIGTERM` → 宽限 10s → `SIGKILL`；进程组整体终止（`setsid` + `killpg`），避免留下孤儿进程（apt 的孤儿会持锁）。
- **资源限制**：`RLIMIT_NOFILE`、`RLIMIT_NPROC` 上限；可选 cgroup v2 限制（内存/CPU）用于无界命令。
- **输出处理**：stdout/stderr 独立捕获、带上限（默认 1MiB/流，超出截断并在结果里标注）；二进制输出自动 base64 或转存 SFTP。
- **输出脱敏**：内置正则脱敏（私钥块、`password=…`、token、JWT、连接串），**落日志前**执行。
- **并发与锁**：同目标上，T1 动作串行（避免 apt/dnf 锁冲突）；R0 探针可并发（上限 4）。

---

## 6. 主控端 DSH 插件设计

### 6.1 插件约定（已核实）

DSH 插件是 CORDIS 函数插件：导出 `name` / `inject` / `apply`，**且不得有 `default` 导出**（`default` 会让 Loader 的 `unwrapExports` 折叠模块从而丢失 `inject`）。

```js
// packages/plugin-host/src/index.js —— 以下形状已对着 DSH 类型声明核实并实测通过
export const name = 'vmprobe'

// 静态注入：缺失即组合错误（fail-fast），避免运行时空引用
export const inject = ['tools', 'approval']

// apply() 保持**同步**：CORDIS 是否 await 异步 apply 未经核实，因此不依赖它。
// 目录加载与存储目录创建改用同步 API（文件极小），工具执行仍全部异步。
export function apply(ctx, config = {}) {
  const engine = createEngine({ dir: config.storageDir ?? DEFAULT_STORAGE_DIR,
                                catalogDir: config.catalogDir,
                                transport: config.transport ?? null })

  // 每个工具都**必须**声明 output:{schema,render} —— 这是 ToolDefinition 的必填字段
  ctx.tools.register({
    name: 'vmprobe_action',
    description: '…',
    parameters: { type: 'object', properties: { … }, required: ['target', 'action'] },
    output: {
      schema: { type: 'object', properties: { status: {…}, plan: {…} }, required: ['status','plan'] },
      render: (_args, value) => [{ type: 'text', text: `…` }],   // → ContentBlock[]
    },
    // 纯函数、可在重放时调用：卡片只依赖 args
    presentCall: (args) => ({ card: 'generic', title: `执行动作 ${args.action} → ${args.target}`,
                              kind: 'execute', rawInput: args.params }),
    presentResult: (args, result) => result.isError ? undefined
                                                    : { card: 'generic', title: '…' },
    timeoutMs: 3600000,
    async execute(args, exec) {
      const plan = await engine.planAction({ … })        // ① R0 只读计划

      if (plan.blocked) return { status: 'blocked', plan, error: plan.blockedReason }
      if (plan.noop)    return { status: 'noop', plan }

      // ② 能力前置检查 —— **必须在申请审批之前**。
      //    对一件做不到的事去征求用户同意，是在浪费用户对审批的注意力。
      if (!engine.canExecute) return { status: 'not_implemented', plan, error: '…' }

      // ③ 审批（仅 R2/R3；R0/R1 已由策略判定免弹）
      if (plan.requiresApproval) {
        if (!ctx.approval || !exec.agent) {
          return { status: 'blocked', plan, error: '按 fail-closed 拒绝执行' }
        }
        const decision = await ctx.approval.request({
          agent: exec.agent,                 // 必填：决定审计事件写进哪个 session
          toolName: 'vmprobe_action',
          callId: exec.callId,               // 可选：把审批提示挂到已流式展示的调用上
          reason: plan.approvalReason,       // ★ 唯一的自由文本通道，一句话说清影响面
          signal: exec.signal,
        })
        if (decision !== 'allowed-once') return { status: 'rejected', plan }  // 非授予一律拒绝
      }

      // ④ 执行 + 验证
      return { status: 'ok', plan, result: await engine.applyPlan(plan) }
    },
  })

  // 注意：**不返回 engine**。CORDIS 会把 apply 的返回值当作 disposer 处理，
  // 返回对象有被误判的风险。
}
```

> 🔧 **v0.1 → v0.2 修正（M0 实测）**：v0.1 里的骨架缺了必填的 `output`，并且把
> `title/risk/target/impact/argv` 传给了 `ctx.approval.request` —— **这些字段并不存在**。
> `ApprovalRequest` 只有 `agent / toolName / callId / reason / signal` 五个字段。
> 因此富 plan（差分、影响面、解析后的 argv）改由 **`execute` 返回值 + `presentCall` 渲染**承载，
> 审批只带一句由 `core/risk.js` 生成的精炼 `reason`。
> 这反而印证了 D7：**必须先把 plan 作为一次独立调用返回，用户才看得到它，然后才谈审批**。

**M0 实际实现位置**（可运行，已被 `tools/checks/verify-plugin.mjs` 逐项校验）：

| 文件 | 内容 |
|---|---|
| `packages/plugin-host/src/index.js` | `name` / `inject` / `apply`，同步 apply，注册 5 个工具 |
| `packages/plugin-host/src/tools.js` | 5 个 `ToolDefinition`（含必填 `output`、`presentCall`） |
| `packages/plugin-host/src/engine.js` | 引擎：目标/目录/计划/审计，**零 DSH 依赖** |

**挂载方式**（✅ **已真机验证** — 见 `ISSUES.md` §9.2）

四种候选形式全部实测过，只有两种能用，且有一条关键的"静默失败"陷阱：

| 形式 | 结果 | 报错 |
|---|---|---|
| 裸 Windows 绝对路径 | ❌ | `Only URLs with a scheme in: file, data, and node are supported... Received protocol 'c:'` |
| `file://` 指向**目录** | ❌ | `Directory import ... not supported (ERR_UNSUPPORTED_DIR_IMPORT)` |
| `file://` 指向**入口文件** | ✅ | — |
| **包名 + `dsh.bundle` patch** | ✅ **采用** | — |

**最终部署形态**：包内自带 patch，并在 `package.json` 声明 `dsh: { bundle: { patch: "./cordis.patch.yml" } }`。
这样对方在 profile 里 `dsh plugin add` 之后**自动成为一层**，**不需要手改用户的 `cordis.patch.yml`**。
（已核实 `dsh-base` / `dsh-web-app` 都是这个形态；未声明 `dsh.bundle` 时 DSH 会明确提示
"installed as a plain dependency, not a profile layer"。）

```jsonc
// packages/plugin-host/package.json —— 插件自己声明成 profile 层
{
  "name": "@vmprobe/plugin-host",
  "main": "src/index.js",
  "dsh": { "bundle": { "patch": "./cordis.patch.yml" } }
}
```

```yaml
# packages/plugin-host/cordis.patch.yml —— 包自带的挂载声明
- insert:
  - id: vmprobe-host
    name: '@vmprobe/plugin-host'   # 包名由 profile 的 node_modules 解析（最稳的形式）
```

**两条必须记住的坑**：

1. ⚠️ **profile 依赖必须用 pnpm 的 `link:`，不能用 `file:`。**
   `file:` 是**版本化拷贝** —— `add` 之后源码改动**不会刷新**（`add` 会直接说 "Already up to date"），
   于是 profile 静默地跑着旧代码。实测撞到过：`node_modules` 里的 `index.js` 与源码不一致、且缺 patch 文件。
   `link:` 建的是 Junction/符号链接，源码即生效。
2. ⚠️ **`--dump-config` 不能用来验证挂载。** 它只合成配置树、**不做 import**，
   所以四种形式（包括错的）在它眼里全都"成功"。必须真的启动一次才能验 —— 而验的时候要用
   `--port 0` 另起临时实例，不要碰正在服务的那个（见 §9 的测试纪律）。

### 6.1.1 容器依赖顺序：定时器为什么必须用 `ctx.inject`

`inject` 的语义是「这些服务必须在插件运行前就绪」。定时器服务**不在** `inject` 里，
于是 `apply()` 可能在它就绪**之前**执行 —— `ctx.interval` 还不存在，
**定时器压根没注册，而且没有任何报错**（生产表现：日报永远不出现）。
这是真机验证才抓到的缺陷（`ISSUES.md` §9.3）。

修法是 `ctx.inject(['timer'], cb)`，而**不是**把 `'timer'` 加进 `inject`：
后者会让"没有 timer 的 profile"里**整个插件加载失败**，而定时日报只是可选特性，不该有这个权力。

| 依赖性质 | 声明方式 | 缺失时 |
|---|---|---|
| **核心必需**（`tools` / `approval`） | 顶层 `export const inject = [...]` | 插件加载失败（fail-fast，正确） |
| **可选特性**（`timer`） | `ctx.inject([...], cb)` | 回调不执行，插件照常加载 + 明确告警 + 落台账 |

同时还暴露了一个更基础的问题：**`ctx.logger` 的输出既不一定进 stdout、也不一定进 DSH 日志文件**，
于是"插件到底加载了没有 / 定时器起来没有"靠看日志答不上来。因此引入**加载台账**
（`<storageDir>/loads.jsonl`，事件流：`load` / `scheduler.started` / `scheduler.disabled` / `scheduler.failed`）。

### 6.2 工具清单（模型可见面）

| 工具 | 风险 | 作用 | 模型典型调用 |
|---|---|---|---|
| `vmprobe_targets` | R1 | 目标 CRUD / 列表 | 「我有哪些虚拟机」 |
| `vmprobe_status` | R0 | 连接状态 + facts 摘要 + 最近一次报告 | 「查看虚拟机状态」 |
| `vmprobe_facts` | R0 | 完整画像（分节查询，避免灌爆上下文） | 「磁盘还剩多少」 |
| `vmprobe_catalog` | R0 | 动作目录 + **基础用法提示**（对应需求「展示并提示基础用法」） | 「你能干什么」 |
| `vmprobe_action` | R0→R1+ | plan/apply/verify 主入口 | 「更新系统」「装 nginx」 |
| `vmprobe_logs` | R0 | 查运行日志/命令日志（按 traceId、动作、时间过滤） | 「昨天那次更新结果如何」 |
| `vmprobe_archive` | R0/R1 | 导出/导入/预览 diff | 「把配置导出，我要换电脑」 |
| `vmprobe_report` | R0 | 结构化状态报告（定时任务与手动共用） | 定时任务触发 |

> 📌 **M0 只注册 5 个**：`vmprobe_catalog` / `vmprobe_targets` / `vmprobe_status` / `vmprobe_action` / `vmprobe_logs`。
> `vmprobe_facts`（需传输层）、`vmprobe_archive`（M3）、`vmprobe_report`（M4）**暂不注册**。
> 理由：**注册一个永远报错的工具，会白占每轮请求的 schema token，并诱使模型去调用它** ——
> 比不注册更糟。宁可等能力就绪再暴露。

**设计要点**：

- **工具数量克制**（目标 8 个，M0 起 5 个）。DSH 里每个工具的 schema 都是每轮请求的固定前缀开销；工具越多，模型选择越容易出错。所以「动作」不被拆成一堆工具（不是 `vmprobe_update_system`、`vmprobe_install_pkg`…），而是**收敛到 `vmprobe_action` + 目录**。这也让新增动作不需要改插件。
- **基础用法提示**（需求 1.2）用两条互补途径落地：
  1. `ctx.systemPrompt.section` 注入一段**简短**用法约定（保活语义、风险级含义、「先 dryRun 再执行」的推荐流程）——注意这会进每轮请求前缀，必须极简；
  2. `vmprobe_catalog` 工具返回完整的「基础用法 + 常用动作 + 示例话术」，按需拉取，不占常驻 token。
- **pin 住 KV cache 友好的写法**：工具 schema 与 description 一旦发布不轻易改动（改 schema 会作废前缀缓存）。

### 6.3 审批接线细节

> ✅ **以下为 M0 核对类型声明后的**准确**签名**（v0.1 曾把不存在的字段传给审批请求）：

```ts
// 真实的 ApprovalRequest —— 只有五个字段，没有承载富文本的通道
interface ApprovalRequest {
  readonly agent: Agent;        // 必填。决定审计事件写进哪个 session，也决定哪个 UI 能应答
  readonly toolName: string;    // 必填。用于展示与审计
  readonly callId?: CallId;     // 可选。让 UI 把审批提示挂到它已流式展示的那次工具调用上
  readonly reason?: string;     // 可选。★ 唯一的自由文本通道：一句话说清「为什么问」
  readonly signal?: AbortSignal;// 可选。中止即撤回提问（结算为 cancelled）
}
type ApprovalOutcome = 'allowed-once' | 'rejected' | 'cancelled' | 'unavailable';
// ApprovalService.request(req): Promise<ApprovalOutcome>
```

关键约束与实践结论：

- **风险级由 plan 决定，不由模型决定**。模型只能选动作与参数；风险级从目录条目 + 运行时判定（如「含内核升级 → R2」）计算。**模型无法自我降级权限** —— 这是关键的不变量，已在 `core/risk.js` 落地并有单测锁定。
- **只有 `allowed-once` 是授予**。`rejected` / `cancelled` / `unavailable` 一律按「不执行」处理；**缺失或抛异常的应答器会返回 `unavailable`，必须 fail-closed**，绝不能「没有审批器就放行」。插件另有自己的二次防线：`ctx.approval` 缺失或 `exec.agent` 缺失时直接返回 `blocked`。
- ⚠️ **`request()` 要求当前有打开的回合（open turn）**；空闲时发起会在写入任何东西之前就被拒绝。因此**定时器驱动的任务无法申请审批** —— 定时任务只能做 R0/R1（§6.4）。
- 每次请求都会写入 `approval/asked` + `approval/decided` 审计事件（DSH 自带），**与我们的命令日志共用 traceId**，于是「谁批的、批了什么、实际跑了什么」三件事可串起来。
- **`R3` 的「复述主机名」不能靠审批请求本身实现**（它没有承载用户输入的字段）。做法是：`ctx.approval.request` 之外，再经问答机制要求用户输入目标主机名并校验一致，然后才继续。M0 已在 plan 上标记 `requireEchoHostname`，实际问答在 M1 接。
- **审批顺序纪律（M0 已实现）**：`blocked` 判定 → `noop` 判定 → **能力前置检查** → 才发起审批。
  即：**绝不对一件做不到的事去征求用户同意**。`tools/checks/verify-plugin.mjs` 专门有一项断言守住它（未接线时必须 0 次审批调用）。

### 6.4 定时状态报告：输出为**按天独立存放的文件**

**需求（已明确）**：
1. 每天固定时间让协从端报告一次虚拟机状态；
2. 报告**不进入对话**，而是以文件形式保存在文件夹里；
3. **文件以时间命名，确保每天的独立存放**。

#### 6.4.1 存放布局与文件内容

```
<storageDir>/reports/<targetId>/<YYYY>/<YYYY-MM-DD>.json
                │              │        └─ 文件名只有数字与连字符（Windows 合法）
                │              └─ 按年分片，避免单目录堆积上万条目
                └─ 经 assertSafeId 校验，防路径穿越
```

一天一个文件，文件内 `runs[]` 承载当天多次运行：

```jsonc
{
  "schema": "vmprobe/report/1",
  "day": "2026-09-14",
  "targetId": "t_vm",
  "createdAt": "2026-09-14T08:00:00.000Z",
  "updatedAt": "2026-09-14T20:00:00.000Z",
  "runs": [
    { "at": "2026-09-14T08:00:00.000Z", "status": "ok",
      "metrics": { "diskUsedPct": 43, "upgradable": 12, "securityUpgradable": 3 },
      "audit": { "hash": "9c02…", "count": 118, "total": 4021 } }
  ]
}
```

#### 6.4.2 三个刻意的决定（每条都对应一个推演出来的坑）

| 决定 | 理由 |
|---|---|
| **日键用 UTC，不用本地时间** | 本地时间遇夏令时会出现"某天 08:00 不存在"或"同一天触发两次"，导致撞名或漏天。报告**内部**另记 ISO 时刻供人阅读 |
| **文件名绝不含冒号** | 朴素做法（RFC3339 时间戳 `2026-09-14T08:00:00Z.json`）在 **Windows 上是非法文件名**。改用 `2026-09-14.json`。顺带好处：**字典序 = 时间序**，列目录即得时间线 |
| **一天一个文件、内含 `runs[]`** | 定时报告与手动报告可能同日发生。"按天独立存放"由文件保证；不丢任何一次由数组保证。写入用临时文件 + rename 原子替换 |

#### 6.4.3 边界行为

- **缺天不补造。** DSH 没运行就是没运行，凭空生成一份"报告"是伪造数据。`findGaps()` 如实算出空缺，让上层能说"9-15 到 9-16 有 2 天没有报告"。
- **目标不可达照样落文件**，内容记 `{ status: 'unreachable', error }`。否则"没有文件"既可能是没跑、也可能是跑了但连不上 —— **这两种情况的处置完全不同，不能靠猜**。
- **保留策略必须存在**：近 90 天全留，更早的每月留 1 号（`pruneReports()`）。一天一文件 × 多目标，不清理会无限膨胀。
  **M2 起它真的会跑**（技术债 #5）：调度器在每天生成报告之后顺带清理一次，幂等键是 UTC 日键
  （与报告本身同一套思路：重启后自动补跑、重复触发无副作用）。清理失败**不影响**报告生成，但要明确告警 ——
  否则报告会无声膨胀。保留天数由 `reportRetentionDays` 配置（默认 90）。
- **报告内容是"趋势 + 异常"，不是 facts 全量倾倒**：「磁盘 / 从 41%→43%（正常）；待更新包 12→19（含 3 个安全更新，建议处理）」—— 这才是定时报告的价值。异常规则见 `buildTrend()`。

#### 6.4.4 与审计链的绑定

每份报告写入时盖**审计锚点**（当前链尾哈希 + 条数）。这样拿报告里的 `audit.hash`
去命令日志里定位，就能知道那份报告生成时系统处于哪个状态点。

> ⚠️ **仍待补**：报告文件**自身**的 sha256 没有记录，因此报告被事后篡改无法检出。
> M1 应把文件 sha256 追加进审计链，形成报告 ↔ 审计双向绑定（见 `ISSUES.md` I11）。

#### 6.4.5 谁来触发（与 `dsh-schedule` 的可用性无关）

> ⚠️ **v0.1 → v0.2 修正**：v0.1 原本推荐「会话内定时 + 插件定时器」双方案。但 M0 用 `--dump-config`
> 实测发现 **`dsh-schedule` 并未组合进 web profile**（`dsh-user-approval` / `dsh-tools` /
> `dsh-storage-json` / `cordis-plugin-timer` / `dsh-jobs-local` / `dsh-permission-presets` 都在，唯独它不在）。
> 既然需求已明确"**报告不进对话**"，方案 A 就不需要了 —— **这条路自然消失，问题不复存在**。

| 触发器 | 机制 | 状态 |
|---|---|---|
| **插件自有定时器（选定）** | `cordis-plugin-timer` 每天到点跑 R0 的 `probe.report`（免审批）→ `engine.generateDailyReport()` → `writeDailyReport()` | ✅ **已实现**：`scheduler.js` + `generateDailyReport()` + `report-builder.js` + 保留策略，均有单测与探针。**尚未真实启动**（定时器接线本身已由 fake ctx 验证） |
| 手动触发 | `vmprobe_report` 工具或 CLI → 写同一天的 `runs[]` | 工具待 M4 注册（引擎方法已就绪） |
| 协从端本地定时（v2） | 守护进程按 cron 本地生成报告落盘；控制器连上后收割 | 适合**控制器长期关机**的场景，需守护进程（D6 升级路径） |

**实现选择：短周期 tick + 幂等判定，而不是「每 24 小时跑一次」**

已静态核实 `ctx.interval(callback, delay): () => void` 是**固定频率**定时器。用它做"每天固定时间"有三重问题：
① 从插件加载时刻起算会**漂移**；② 中途重启会**错位**（可能整天不触发，或一天触发两次）；③ 夏令时会算错。

因此改为**每 60 秒 tick 一次，判定「今天到点了吗？今天已经生成过了吗？」**：

| 收益 | 说明 |
|---|---|
| **崩溃恢复免费** | 重启后"今天还没生成"仍然成立 → 自动补跑当天，无需额外逻辑 |
| **重复触发无副作用** | 幂等键就是 UTC 日键，与"一天一个文件"天然吻合 |
| **无漂移/夏令时问题** | 不依赖"上次触发时刻"，只依赖墙钟与日键 |
| 代价 | 每分钟一次空转判定（可忽略） |

**边界**：进程停了三天，那三天的文件就是**不存在** —— 由 `findGaps()` 如实报缺，
而不是事后编一份。**没有采集能力时不写文件**（宁可不产生报告，也不产生假报告）。

> **注意 open-turn 限制**：`ctx.approval.request` 要求有打开的回合，因此**定时器驱动的任务无法申请审批**。
> 这不是问题 —— 定时报告是 R0 只读动作，本来就不需要审批。但**定时任务永远只能做 R0/R1**，R2/R3 必须经对话发起。


### 6.5 客户端 UI 贡献

参考 `dsh-client-ui-jobs` 的做法（贡献一个 slot 条目，数据经 host 推送帧到达，客户端不发 RPC）。

> ✅ **M0 已核实存在的 slot id**（读 `dsh-client-ui-conversation/lib/types/client/contract/slots.d.ts`）：
> `conversation.session.header.actions`、`conversation.session.header.utilities`、
> `conversation.details.tool`、`conversation.chat.node`、`conversation.chat.commandview`、
> `conversation.chat.turnTail`、`conversation.view`、`conversation.composer`、
> `conversation.input.{left,right,plan,dock}`、`conversation.hero.*`。
> 注意 `conversation.composer` 已承载**审批提示 UI**（`ApprovalComposerProps`）——
> 也就是说审批弹窗由 DSH 现有组件渲染，我们的插件**不需要**自建审批界面。

| Slot | 内容 |
|---|---|
| `conversation.session.header.actions` | 连接状态徽标（● 已连接 vm-a）+ 目标切换 Popover |
| `conversation.details.tool` | `vmprobe_action` 的 plan 详情面板（差分明细 + 风险色带 + 解析后的 argv） |
| 设置页（plugins/settings slot） | 目标管理（含**掩码密码录入**）、风险策略、导入导出、日志查看 |
| 工具结果渲染 | 经 `presentCall` / `presentResult` 声明意图（见 §6.1），**不需要写自定义渲染组件** |
| 自有 locale 命名空间 | `vmprobe.*`，中英双语 |

**状态推送**：连接状态变化、心跳结果、长任务进度，通过 host→client 帧推给 UI（与 `session/jobs` 帧同构思路）。**数据是 host 算好的，客户端只渲染**，避免客户端持状态。

**渲染意图的两条已核实路径**（比自建组件省事得多）：

| 意图类型 | 形状 | VMProbe 用法 |
|---|---|---|
| `GenericCallView` | `{ card:'generic', title, kind?, rawInput?, content? }` | 动作卡片：`kind:'execute'`，标题「执行动作 system.update → vm-a」 |
| `GenericResultView` | `{ card:'generic', title?, content? }` | 执行结果卡片（失败时返回 `undefined` 保留原始内容，让错误完整可见） |
| `DiffCallView` | `{ card:'diff', title, diffs:[{path,oldText,newText}] }` | **后续可用于改配置类动作**：把 `/etc/ssh/sshd_config` 的改动渲染成真正的 diff 卡片 |

两者都是**纯函数且会在会话重放时被调用**，因此只能依赖 `args`（和 `result`），不得读运行时状态。

---

## 7. 存储、日志与审计

### 7.1 主控端存储布局

```
<storageDir>/                       （默认 $DSH_HOME/vmprobe，尊重 DSH_HOME）
├── targets.json                    目标定义（**不含任何凭据**，只有 authRef 引用）
├── policy.json                     风险策略、命令白名单、免打扰授权（带 TTL）
├── facts/<targetId>.json           最近画像（+ 历史摘要环形缓冲 30 条）
├── runs/<runId>.log                ✅ 已实现（M2）：单次执行的完整输出 + 校验结论，
│                                     审计只留 {path, sha256, bytes} 引用（见 D7.6）
├── loads.jsonl                     ✅ 已实现：加载台账（插件/定时器到底起没起来）
├── keys/<targetId>                 ✅ 已实现：每个目标一把专用密钥（免密事务用）
├── logs/
│   ├── audit.jsonl                 ✅ 已实现：逐条 exec 的哈希链审计（启动时重放，按 8MiB 轮转）
│   └── run.jsonl                   ⏳ 生命周期事件（尚未单独落文件；当前在审计与台账里）
├── reports/<targetId>/<YYYY>/<YYYY-MM-DD>.json
│                                   ✅ 已实现：每日状态报告，一天一文件、按天独立
└── vault.bin                       ⏳ 可选：加密凭据库（scrypt + AES-GCM，M1）
```

**已实现 vs 规划**：`audit.jsonl`、`reports/`、`facts/`、`runs/`、`loads.jsonl`、`keys/` 均已落地并有测试；
凭据仍走 DSH 的凭据服务（`~/.dsh/.credentials.yaml`），**本项目不自己存凭据**，因此 `vault.bin` 预计不会实现。
审计**内存窗口**默认保留 5000 条（可配 `maxAuditRecords`），完整历史在文件里 ——
这样既能防内存泄漏，又不丢证据（见 `ISSUES.md` F12）。

**运行记录 vs 审计的分工**（M2 新增，别混淆）：

| | 审计（`logs/audit.jsonl`） | 运行记录（`runs/<runId>.log`） |
|---|---|---|
| 内容 | 事件流：谁在什么时候对哪个目标做了什么、结果摘要 | 单次执行的完整输出（逐条命令、stdout/stderr、校验结论） |
| 防篡改 | 哈希链（可检出改动） | 内容本身不加密，但 sha256 记在审计里，可核对 |
| 体量 | 小、可控（会轮转） | 可能很大（默认上限 4 MiB，超出截断并标注） |
| 脱敏 | 写入前过 redactor | **同一套** redactor（两条规则必然漂移，见 I8） |

### 7.2 两套日志（对应需求 2.2）

**A. 运行日志 `run.jsonl`** —— 「系统发生了什么」

```jsonc
{ "ts":"2026-09-14T10:00:00.123Z", "level":"info", "traceId":"…",
  "event":"transport.connect.start", "target":"t_a1b2", "transport":"embedded",
  "authMode":"password", "attempt":1 }
{ "ts":"…", "level":"warn", "event":"approval.unavailable", "traceId":"…",
  "action":"system.update", "decision":"fail-closed" }
```

**B. 命令使用日志 `command.jsonl`** —— 「到底跑了什么」（审计核心）

```jsonc
{ "ts":"2026-09-14T10:00:05.010Z", "traceId":"…", "runId":"r_7f3c", "target":"t_a1b2",
  "side":"agent", "action":"system.update", "actionVersion":1,
  "params":{"securityOnly":false,"exclude":["linux-*"]},
  "risk":"R2", "riskEscalatedBy":"kernelUpgradePending",
  "resolvedArgv":[["apt-get","update"],["apt-get","-y","-o","Dpkg::Options::=--force-confold","dist-upgrade"]],
  "approval":{"asked":"ap_91", "decided":"allowed-once", "at":"…", "asker":"web"},
  "exit":0, "durationMs":74213, "stdoutRef":"runs/2026-09/r_7f3c.stdout",
  "stdoutSha256":"…", "changed":[{"pkg":"linux-image-generic","from":"6.14.0-10","to":"6.14.0-11"}],
  "verify":"ok", "rebootRequired":true,
  "prev":"a3f1…", "hash":"9c02…" }
```

**字段设计理由**：
- `resolvedArgv` 记录**解析后的真实命令**（而不是动作 id）——审计要看的是实际执行了什么。
- `changed[]` 让「更新了哪些包」可追溯，而不是只有一个 exit 0。
- `stdoutRef` + `stdoutSha256`：大输出不塞日志，哈希保证不被篡改。
- 模型**看不到**完整命令日志（会灌爆上下文），只通过 `vmprobe_logs` 拿聚合摘要。

### 7.3 哈希链与双端交叉核对

- 每条记录含 `prev`（上一条的 hash）+ `hash`（自身内容 + prev 的 SHA-256）。**篡改任一条，后续全部断链**。
- 协从端在 `/var/log/vmprobe/agent.jsonl` record **同一条 run 的独立视角**（自己记录的 argv、uid、退出码）。
- 核对命令：`vmprobe logs verify --runId r_7f3c` 拉取两端记录比对，不一致即告警（提示「主控端日志被改」或「协从端被替换」）。
- 这是「探针」类工具应有的诚实性：**日志不能只由被审计方保管**。

### 7.4 日志轮转与保留

| 端 | 位置 | 轮转 | 默认保留 |
|---|---|---|---|
| 主控端 | `<storageDir>/logs/audit.*.jsonl` | ✅ **已实现**：按大小 8MiB 轮转 | 内存窗口 5000 条；文件按需保留 |
| 协从端 | `/var/log/vmprobe/*.jsonl` | ⏳ logrotate（daily + 64MiB），M1 | 30 天 / 100MiB |

上限必须存在：命令日志会随心跳线性增长（60s 一次=每天 1440 条）。
内存侧已由 `maxAuditRecords` 封顶（实测 20k 条 ≈ 16.5MiB 且每条算一次 SHA-256）；
文件侧按大小轮转。

**轮转实现里有一个必须记住的细节**（推演探针抓到的真 bug）：
轮转**本身**也要往链里追加一条 `audit.rotate` 记录，因此**顺序是**「先轮转、再追加本条」。
若反过来（先把自己的记录加入内存链、再轮转），那条轮转记录的 `prev` 会指向**尚未落盘的本条**，
新文件里两条记录的先后与链序相反 —— **磁盘上的哈希链就断了**，而且断得很隐蔽。

轮转记录接续旧文件的尾哈希，因此 **`verifyAuditFull()` 可以跨全部轮转文件校验**（实测 9 次轮转、10 个文件、69 条记录，链完好）。

> ⚠️ **诚实的局限**：整套审计是**无密钥**的 sha256 链。它可靠检出意外损坏与单侧改动，
> 但**挡不住**同时拥有审计目录写权限且愿意重算整条链的攻击者。
> 要真正抗伪证需要 **HMAC**（密钥放凭据库、不进归档）—— 未实现，不该假装做了。

### 7.5 脱敏（落盘前执行，不可绕过）

✅ **已实现**（`core/src/redact.js`），落在**两个必经关口**：

| 关口 | 位置 | 作用 |
|---|---|---|
| 审计写入 | `engine.record()` | **先脱敏再入链**，因此哈希链覆盖的是脱敏后内容 —— 审计要能证明"发生过什么"，但不能成为秘密的第二个副本 |
| 工具出口 | `createTools()` 的统一包装 | 任何工具抛出的错误都先脱敏再出，避免远端回显把凭据带进模型上下文 |

覆盖的形态（每条都有单测锁定）：私钥块、JWT、URL 内嵌凭据（`scheme://user:pass@`）、
命令行凭据（`curl -u user:pass`）、`Bearer <token>` 头、AWS access key、
以及 `key=value` / `"key": "value"` 两种写法，并显式列举 `access_token`/`refresh_token`/`client_secret`/`private_key` 等复合名。

两个反直觉的细节（都是单测逼出来的）：

1. **`\b` 在 JSON 里不成立**：`{"token": "x"` 中 `{` 与 `"` 之间没有单词边界，
   用 `\btoken\b` 会**完全匹配不到** —— 而 JSON 恰恰是最常见的形态。改用负向后顾。
2. **脱敏必须幂等**：替换标记本身不能再被同一规则匹配，否则第二遍会把
   `[REDACTED:key-value` 再当一次值，输出累积成 `...value]]`。用负向先行 `(?!\[REDACTED)` 挡住。

**键名判定是单一实现**：`isSecretKeyName()` 同时供 `assertSecretFree`（写入拒绝）
与 `redact.js`（输出脱敏）使用 —— 两处各写一套规则迟早会漂移成"一边拦一边放"。

**同时保留"被脱敏过"的事实**：`redactDeep` 返回 `redactedPaths` 并记入审计。
既看不到秘密，又**知道秘密曾经经过** —— 完全抹掉痕迹会让"秘密流经这里"变得不可发现。

**审批时展示给用户的 argv 也走同一脱敏**（避免密钥出现在 UI 与截图里）。

---

## 8. 关键流程时序

### 8.1 首次接入 + 安装协从端

```
用户/模型               插件                 传输层                 被控 VM
   │  target.add(host,user)  │                     │                     │
   ├────────────────────────►│  校验(不含密码)      │                     │
   │                         │  发现无凭据          │                     │
   │◄── needsSecret ─────────┤                     │                     │
   │  [UI 掩码输入密码]       │                     │                     │
   ├────────────────────────►│  写入凭据库(不入会话) │                     │
   │                         ├── connect(password) ─►                     │
   │                         │                     ├── handshake ───────►│
   │◄── 主机指纹待确认 ───────┤  指纹与已固定值比对   │                     │
   │  [R1 审批：固定指纹]     │  (TOFU；不符则拒绝)   │                     │
   ├────────────────────────►├─────────────────────►│                     │
   │                         │  exec: os-release, uname -m, init 探测     │
   │                         │◄──────────────────── 画像 v1 ─────────────┤
   │                         │  选择二进制形态(A/B)  │                     │
   │                         ├── SFTP put vmprobe-linux-x86_64 ──────────►│
   │                         │  exec: chmod +x && sha256sum 校验           │
   │◄── R1 审批：安装协从端 ──┤  exec: installer --mode=system             │
   │                         │◄──────────────────── selfcheck ok ────────┤
   │                         │  保存 target + facts  │                     │
   │◄── 「vm-a 已接入（ubuntu 26.04, 4C/8G, 待更新 12）」 ─────────────────┤
```

**要点**：密码在第一次成功连接后**不再需要**（若启用免密）；插件**不把密码写入 targets.json**，只存 `authRef` 引用。

### 8.2 免密切换事务（D3 的落实，需求示例 3）

```
   │  vmprobe_action action=ssh.passwordless.enable target=vm-a
   ▼
[1] plan（R0 只读）
    · 检查远端 sshd：PubkeyAuthentication? AuthorizedKeysFile? StrictModes?
      ↓ 若 pubkey 被禁用 → plan 返回 blocked:["需先改 sshd_config"]，并给出后续 R2 动作建议
    · 检查 ~/.ssh 权限、家目录权限（StrictModes 会因组可写而拒绝）、SELinux 上下文
    · 生成本地专用密钥对（ed25519，注释 vmprobe:vm-a:<keyid>）
[2] ★ R3 审批（要求复述主机名 vm-a）
    展示：「将向 u@vm-a 的 ~/.ssh/authorized_keys 追加一把专用公钥；
           指纹 SHA256:ab12…；该密钥可随时单独撤销；不改动 sshd 全局配置」
[3] apply
    · 备份 authorized_keys → authorized_keys.vmprobe.<ts>.bak
    · 幂等追加（已存在同 keyid 则跳过，避免重复行）
    · 校正权限：~/.ssh 0700、authorized_keys 0600、家目录组不可写
    · 记录 backupPath 以便回滚
[4] ★ 验证（关键）：另开一条全新连接
    · auth: publickey only, IdentitiesOnly=yes, BatchMode=yes, 超时 10s
    · 成功 → 继续；失败 → **回滚**（恢复备份、删新密钥引用）并保留旧连接
[5] 切换
    · 关闭旧的密码认证会话（主动切断 ← 需求原文的「主动切断链接」）
    · 内存中抹除密码；targets.json 的 authRef 从 password → key
[6] 以免密方式重新连接（需求原文的「再以免密方式登录一次」）
    · 全新 embedded 连接，只带 key → 跑 probe.facts 复核 → 记录 authMode 变更事件
[7] 收尾
    · UI 徽标从「密码」变「密钥」；输出「已切换免密；如需撤销：action ssh.passwordless.disable」
    · 写审计：包含 keyid、新增行 sha256、耗时、verified=true
```

**失败分支全部保持「至少一条可用路径」**：

| 失败点 | 行为 |
|---|---|
| sshd 禁用 pubkey | 不写任何东西；返回 blocked + 建议（改 sshd_config 为独立 R2 动作，含 `sshd -t` 校验 + reload） |
| 权限位导致 StrictModes 拒绝 | 尝试校正权限；若校正失败 → 回滚、报告具体路径与期望权限 |
| 验证连接超时/拒绝 | 回滚 authorized_keys 追加；旧密码连接保持；报告原始 stderr |
| 切换过程中旧连接已断 | 用密钥再试；仍失败 → 明确告知「需通过控制台恢复，备份路径：…」 |

### 8.3 更新系统（需求示例 4）

```
[1] check → { count:12, sizeBytes:412MB, kernelUpgradePending:true, rebootRequired:false }
[2] plan  → 差分 + 影响面：12 包（含内核 linux-image-generic 6.14.0-10→11）
[3] 风险从 R1 **提升为 R2**（因 kernelUpgradePending）→ 审批文案带上「含内核升级，更新后需重启生效」
[4] 建议前置：snapshotCapable=lvm → 提示「可先做快照（独立 R2 动作）」
[5] apply（R2 已批）
    · ctx.jobs 建后台任务；stdout 流式写入 runs/<runId>.stdout + 流式推给 UI
    · 远端落地 /var/log/vmprobe/runs/<runId>.log（断连可续读）
    · 串行锁：同目标其他 T1 动作排队（避免包管理器锁冲突）
[6] verify → 复查 count；解析 changed[]（对比升级前后版本）
[7] 收尾 → rebootRequired? 提示「需重启，是否执行 system.reboot（R3，将中断所有服务）」
             失败 → 返回原始 stderr 摘要 + 日志引用，不吞错
```

### 8.4 定时状态报告（§6.4 方案 B）

```
每天 08:00（ctx.timer）
  └─ 对每个 target 并发跑 R0 动作 probe.report（免审批）
       └─ 采集：负载/内存/磁盘/待更新/服务异常/上次重启时长/新监听端口
       └─ 与上一份报告对比 → 生成趋势与异常标记
       └─ 落 storage reports/<targetId>/<date>.json
       └─ 异常（磁盘 >85%、有待处理安全更新、服务 down）→ 主动提示
用户随时问「最近报告」→ vmprobe_report 返回聚合视图（而非逐条倾倒）
```

### 8.5 导入 / 导出

```
导出：vmprobe_archive { op:export, path:"D:\\vm-backup.vmpz", includeLogs:true, includeSecrets:false }
  ├─ 采集 targets / policy / catalog 覆盖 / facts / (可选) logs
  ├─ 脱敏：内网 IP、监听端口按策略；日志中的密钥/口令强制脱敏
  ├─ 密钥：默认不含；--include-secrets 时必须提供口令 → scrypt+AES-GCM 加密
  ├─ 归一化：路径分隔符统一为 '/'，剔除绝对路径与 OS 专有字段
  ├─ manifest.json（schemaVersion / 版本 / created_at / 每文件 sha256）
  └─ 打包 zip（Windows 友好，无需 zstd 依赖）

导入：vmprobe_archive { op:import, path:"…", mode:"merge|replace", dryRun:true }
  ├─ 校验 schemaVersion → 需要时按迁移脚本升级
  ├─ 校验 sha256；校验通过前不写任何东西
  ├─ **差异预览**（dryRun）：新增 N 个目标 / 冲突 M 个 / 指纹变化 K 个 / 失效凭据 J 个
  ├─ 主机指纹变化 → 单独列出并要求逐条确认（防归档被替换成指向攻击者的配置）
  ├─ 冲突策略：merge（默认，保留本地）/ replace / rename-on-conflict
  └─ 提交后重建索引；凭据**不导入**（见 §11.4）
```

---

## 9. 安全模型

### 9.1 威胁模型

| 威胁 | 场景 | 对策 |
|---|---|---|
| **T1 凭据泄露（主控端）** | 密码/密钥被读到 | 密码仅密码认证阶段短暂存在于内存；disk 上只有 authRef/加密 vault；日志脱敏不可绕过；凭据**不进会话上下文与归档** |
| **T2 凭据泄露（会话日志）** | 用户在聊天里打密码 → 永久留档 | D4：密码只经掩码 UI / CLI 录入，工具返回 `needsSecret` 引导 |
| **T3 MITM** | 冒充目标虚拟机 | 主机密钥 fingerprint 固定（TOFU + 变更即拒绝并要求显式批准）；不禁用 StrictHostKeyChecking |
| **T4 模型越权** | 模型幻觉出危险命令 / 自我降级风险级 | 接口是动作目录（非任意 shell）；**风险级由目录+运行时判定，模型不可指定**；每条 R1+ 强制审批；T3 默认关闭 |
| **T5 注入** | 参数里塞 `; rm -rf /` | 动作不经 shell（argv 数组 + execve）；T2 白名单校验；T3 才允许 shell 且强制审批 |
| **T6 被控端持久化后门** | 协从端本身成为后门 | 二进制由主控端推送并校验 sha256；无 TCP 监听（守护模式仅 unix socket + 0700）；`uninstall --purge` 彻底清理；版本指纹可核对 |
| **T7 审计伪造** | 有人改日志掩盖操作 | 双端独立记录 + 哈希链 + `logs verify` 交叉核对 |
| **T8 归档投毒** | 导入的归档里指纹被换成攻击者主机 | 导入必须先校验 sha256；指纹变化逐个确认；默认不导入密钥 |
| **T9 本地提权面** | 探针被用作提权跳板 | sudoers 用**窄规则**（见 9.3），而非 `NOPASSWD: ALL`；最小固定 PATH；环境净化 |
| **T10 无限权限授予** | 「永久允许」被滥用 | DSH 审批 seam 本身是 `allowed-once`；插件自建授权仅限 R0/R1 且带 TTL；R2/R3 永不授权 |

### 9.2 主机密钥校验

- 首次连接：显示 `SHA256:…` 指纹 + 密钥类型，经 R1 审批后固定（TOFU）。
- 之后再连：**严格比对**。不符 → 连接中止 + 高优先级告警（提示「可能是重装、也可能是中间人」），要求显式 `ssh.hostkey.rotate`（R3）才接受新指纹。
- 归档导入时对每个目标的指纹做差异提示（T8）。
- 不从 `~/.ssh/known_hosts` 静默继承信任（native 后端可选继承，需配置项显式开启）。

### 9.3 协从端最小权限

**不要**生成 `vmprobe ALL=(ALL) NOPASSWD: ALL`。改为按目录生成窄规则：

```
# /etc/sudoers.d/vmprobe  （由 agent.install 生成，安装时经 R2 审批展示全文）
Cmnd_Alias VMPROBE_R0 = /usr/local/lib/vmprobe/vmprobe probe *, \
                        /usr/local/lib/vmprobe/vmprobe action run pkg.upgradable *
Cmnd_Alias VMPROBE_R1 = /usr/bin/apt-get update, /usr/bin/apt-get -y dist-upgrade, \
                        /usr/bin/systemctl restart nginx
vmprobe-user ALL=(root) NOPASSWD: VMPROBE_R0, VMPROBE_R1
Defaults!VMPROBE_R1 env_keep += "DEBIAN_FRONTEND"
```

- 用 `visudo -c` 校验语法后才落地。
- 新增动作若需要新特权命令 → 需要重新生成 sudoers 片段（独立的 R2 动作，审批时显示 diff）。
- 无 sudo 时降级为**非特权模式**：只能做 R0 探针 + 用户级动作（明确告知能力边界，不静默失败）。

### 9.4 凭据存储（跨平台）

| 平台 | 方案 |
|---|---|
| Linux | 优先 `libsecret`/`secret-tool`（如可用）；否则 `~/.dsh/vmprobe/vault.bin`（scrypt KDF + AES-256-GCM，主口令经 CLI 无回显录入，0600） |
| Windows | 无内置 DPAPI 的 Node 绑定（DSH 自带 `koffi` FFI 可调 `CryptProtectData`，但依赖 DSH 内部件，不作为 v1 依赖）→ v1 用同一个加密 vault + 明确的文件 ACL（用户 profile 目录默认已限制）；v2 可选接 DPAPI |
| 密钥文件 | 存 `~/.dsh/vmprobe/keys/<keyid>`（POSIX 0600；Windows 依赖 profile ACL），可选口令保护 |

**诚实说明**：主口令保护的 vault 在 Windows 上并不比「OS 账户隔离」强多少；真正的防线是「凭据不落地明文 + 不进日志 + 不进归档」。这一点在设计上已保证，但**不能夸大** vault 的安全性。

### 9.5 危险动作的护栏

- `system.reboot` / `system.shutdown`：R3 + 复述主机名 + 提示「将中断所有服务」+ 建议先快照。
- 磁盘/分区、`rm -rf` 类：T3 才可能，默认关闭，且目录级黑名单（`/etc/fstab`、`/boot`、块设备写入）永远拒绝。
- `sshd_config` 修改：强制 `sshd -t` 语法校验 + 延迟 reload + 自动回滚计时器（若 60s 内主控端未确认连接仍可用 → 自动还原备份）。
- 生产目标标记（`tags: [prod]`）：可配置为「需二次确认 + 禁止 R3 免打扰」。

---

## 10. 跨平台与发行版兼容

### 10.1 主控端

| 关注点 | Windows | Linux |
|---|---|---|
| SSH 传输 | **ssh2（纯 JS）**，无需 OpenSSH/plink/sshpass | 同左；可选 native 后端复用 `~/.ssh/config`、agent、ProxyJump |
| 路径 | `path.join` + 统一内部 `/` 语义；归档内一律 `/` | 同左 |
| 权限位 | 无 chmod → 依赖 profile ACL + vault 加密；文档明示 | `chmod 600` |
| 换行 | 归档与日志一律 `\n`（LF），不做 CRLF 转换 | — |
| 长任务 | `ctx.jobs` 后台任务 + 流式输出（既有能力） | 同左 |
| 定时 | `ctx.timer`（进程内），DSH 关闭即不跑 | 同左；若要 7×24 需 systemd（可选项，v2） |

### 10.2 协从端兼容矩阵

| 维度 | 覆盖 | 备注 |
|---|---|---|
| 发行版系 | debian/ubuntu、rhel/centos/rocky/alma/fedora、suse、arch/manjaro、alpine | 动作按 `ID` / `ID_LIKE` 分流 |
| libc | glibc、musl | 静态二进制规避；sh 降级形态保底 |
| arch | x86_64、aarch64、armv7、riscv64 | 交叉编译产出 |
| init | systemd、openrc、sysvinit、runit | 服务动作按 init 分流；非 systemd 缺失能力如实报告 |
| 只读/不可变 | Fedora Silverblue、openSUSE MicroOS | 降级到用户级安装 + 不能做的动作明确 block |
| 无 systemd 容器 | docker/podman 内的发行版 | `virt.type=container`，跳过服务/重启类动作 |
| 最小化系统 | busybox、无 curl/wget | **二进制经 SFTP 推送**（关键：不依赖远端下载能力） |
| 特殊文件系统 | 家目录加密、SELinux enforcing | plan 阶段探测并给出具体阻塞原因 |

**兼容性原则**：**探测优先、能力声明、绝不猜测**。任何动作在执行前必须确认「所需能力已由 facts 声明为可用」；不可用就 `blocked` + 原因 + 建议，而不是失败一半。

---

## 11. 归档与迁移（需求 2.3）

### 11.1 归档格式（`.vmpz`，实为 zip）

```
vm-backup-20260914.vmpz
├── manifest.json          schemaVersion, generatorVersion, createdAt, host OS,
│                          每文件 sha256, 是否含密钥/日志的标志
├── targets.json           目标定义（无凭据，仅 authRef 引用）
├── policy.json            风险策略、白名单
├── catalog/*.yaml         用户自定义动作
├── facts/*.json           最近画像（可选）
├── reports/**             定时报告历史（可选）
├── logs/*.jsonl           已脱敏日志（可选）
└── secrets.enc            仅 --include-secrets：scrypt+AES-GCM 密文（含提示语，不含口令）
```

### 11.2 兼容性与迁移

- `schemaVersion` 语义化；导入时 **版本高于本机 → 拒绝**（明确报「请升级主控端」）；低于 → 按注册的迁移函数逐级升级（`1→2→3`），每步可单测。
- 未知字段：**保留并告警**（不静默丢弃，避免降级导入时丢数据）。
- 跨平台归一化：路径统一 `/`；剔除 `drive letter`、注册表路径等 OS 专有字段；时间戳统一 UTC RFC3339。

### 11.3 脱敏策略（导出时可选档位）

| 档 | 内容 |
|---|---|
| `minimal` | 仅目标+策略（默认） |
| `standard` | +facts+报告，**内网 IP/端口打码**（`10.0.0.5` → `10.0.0.x`） |
| `full` | 全部含日志，日志强制脱敏（凭据永不含） |

### 11.4 凭据为何不随归档迁移

**决策**：归档**默认不含任何密码、私钥、口令**，只含 `authRef` 引用。

**理由**（与 §D4 同一逻辑）：归档会被拷到 U 盘、网盘、另一台机器；一旦含密钥，它就从一个「配置备份」变成一个「凭据分发物」。而且跨平台迁移后，**目标机通常也换了**（新环境重新生成密钥反而更干净）。

**迁移后的体验**：导入后列出「需要重新录入凭据的目标」清单，逐个用掩码 UI 补录即可——一次几十秒，代价远小于密钥泄露。

**若确实需要**（例如整机搬迁、离线环境）：`--include-secrets` 必须提供口令，产出 AES-256-GCM 密文，且**明确告知这是风险操作**。

---

## 12. 数据模型

```ts
Target {
  id: string                  // t_a1b2
  label: string               // "vm-a"
  host: string; port: number; user: string
  authRef: { kind: 'password'|'key'|'agent'; ref: string }  // 只存引用
  hostKey: { algo: string; fingerprint: string; pinnedAt: string; trust: 'pinned'|'unverified' }
  transport: 'embedded'|'native'|'auto'
  tags: string[]              // ['prod']
  agent?: { version: string; mode: 'cli'|'daemon'; installedAt: string; binarySha256: string }
  lastSeenAt?: string
  factsHash?: string          // 指向 facts/<id>.json
}

Action {
  id: string; version: number
  side: 'agent'|'controller'
  title: Record<locale,string>; summary: string
  risk: 'R0'|'R1'|'R2'|'R3'|'dynamic'
  params: JSONSchema
  requires: { root: boolean; distros: string[]; binaries: string[] }
  idempotent: boolean; timeoutMs: number
  check?: ProbeRef; apply: Record<distro, CmdSpec>; verify?: ProbeRef
  rollback?: { strategy: string; snapshotBefore?: boolean }
}

Plan {
  traceId, targetId, actionId, params
  noop: boolean
  risk: 'R0'..'R3'; riskEscalatedBy?: string
  resolvedArgv: string[][]
  impact: { summary: string; changedEstimate: number; rebootRequired: boolean;
            diskImpactMb?: number; downTimeHintSec?: number }
  blocked?: { reason: string; suggestion?: string }[]
  rollbackHint?: string
}

Run {
  runId, traceId, targetId, actionId, plan, approvalId
  startedAt, endedAt, exit, status: 'ok'|'failed'|'partial'|'rejected'|'unknown'
  stdoutRef?, stdoutSha256?, stderrRef?, changed: Change[]
  verify: { status: 'ok'|'failed'|'skipped'; detail: any }
  audit: { prev: string; hash: string }
}
```

---

## 13. 目录结构与技术栈

```
work/vmprobe/
├── packages/
│   ├── core/              # 纯逻辑：目标/目录/策略/计划/运行/审计链/归档（零 DSH 依赖，可单测）
│   ├── transport/         # SshTransport：embedded(ssh2) / native(openssh+ControlMaster)
│   ├── catalog/           # 内置动作 YAML + 加载器 + 校验（schema 严格校验，未知字段拒绝）
│   ├── plugin-host/       # DSH host 插件（name/inject/apply；tools/approval/jobs/timer/storage）
│   ├── plugin-client/     # DSH 浏览器插件（slot 贡献 + locale + 设置页 + 结果渲染）
│   └── cli/               # 独立 CLI/TUI（自检、救援、CI 场景；不依赖 DSH）
├── agent/
│   ├── bootstrap.sh       # POSIX sh 单文件引导（探测 + 安装）
│   ├── cmd/vmprobe/       # Go 静态二进制（CGO_ENABLED=0）
│   ├── fallback/          # 纯 sh 降级形态（只 R0 + 简单动作）
│   └── packaging/         # systemd unit / logrotate / sudoers 模板
├── docs/                  # 本设计文档 + 动作编写指南 + 安全说明
├── tests/                 # 单测 + 用容器（docker/podman）跑多发行版集成测试
└── scripts/               # 交叉编译、打包、离线包生成
```

**技术栈选择理由**：

| 部件 | 选型 | 理由 |
|---|---|---|
| 主控端 | TypeScript / Node（ESM） | DSH 本体是 Node；插件必须在同进程；`ssh2` 生态成熟 |
| 协从端 | Go（静态） + POSIX sh 降级 | 静态单文件、无依赖、跨 arch 交叉编译简单；sh 形态覆盖极端环境（不用 Python，因为最小化系统不保证有；不用 Node，体积大） |
| 动作目录 | YAML | 人可读可写、可评审、可 diff（运维最关心「改了哪条命令」） |
| schema 校验 | typebox / zod（DSH 已自带） | 工具参数与动作参数共用一套校验 |
| 归档 | zip（Node 内置可解，Windows 友好） | 避免引入 zstd 原生依赖 |
| 集成测试 | docker/podman 多发行版矩阵 | 「任意发行版」必须靠真容器矩阵验证，不能靠声明 |

---

## 14. 里程碑与验收

| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| **M0 骨架** | 传输层（ssh2 单连接复用）+ 目标存储 + 插件挂载跑通 + `vmprobe_status/facts` + 哈希链日志 | 在 DSH 界面问「查看虚拟机状态」返回真实 facts；空闲 30 分钟后命令 <200ms；插件本地 `link:` 挂载方式确认 |
| **M1 动作核心** | 动作目录 + 风险分级 + `check/apply/verify` + 审批接线 + plan 卡片渲染 | 「更新系统」在 Ubuntu 容器上完成 plan→审批→执行→verify 全链路；拒绝路径同样留痕 |
| **M2 免密与引导** | 密钥生命周期 + 免密切换事务 + SFTP 推送安装 + 卸载 | 5 系发行版全部完成密码接入→免密切换；**人为破坏验证步骤时旧连接仍可用（不锁死）** |
| **M3 日志与归档** | 双端审计 + `logs verify` + 导出/导入 + 迁移 + 脱敏 | Windows 导出 → Linux 导入后功能等价；篡改日志能被 `verify` 检出 |
| **M4 进阶** | 守护进程 + unix socket + 本地定时 + 流式任务 + 多目标 fan-out + 快照回滚 | 关闭 DSH 一天后重连，能收割到本地生成的报告 |
| **M5 硬化** | 指纹固定、sudoers 窄规则生成、T2/T3 护栏、模糊测试目录、威胁模型复查 | 威胁模型 T1–T10 逐条有对应对策与测试用例 |

**M0 三个「必须最先验证」的技术假设**（避免后期返工）：
1. `link:` 本地插件能否被 `cordis.patch.yml` 正常加载（含客户端插件的 HMR 是否需要 `pnpm run dev:web`）。
2. `ctx.approval.request` 的实际签名与返回值在 web 组合下的行为（尤其 `unavailable` 路径）。
3. `ssh2` 在内网/高延迟链路上的 keepalive 稳定性，以及单连接多 exec channel 的并发上限。

---

## 15. 风险与未决问题

### 15.1 决策状态

**已拍板（2026-09-14）**：

| # | 问题 | 决定 | 落地情况 |
|---|---|---|---|
| **D5-a** | R0 只读是否也要弹窗？ | ✅ **R0/R1 免弹但留痕，仅 R2/R3 弹窗**（你选的第三项更省事方案的邻项；R1 免弹） | 已落地 + 单测锁定（`core/risk.js`） |
| **新** | 目标是单台还是多台？ | ✅ **单台为主，多台是加分项** → UI 可极简：状态徽标 + 无目标列表 | 设计支持多目标，UI 走简化路径 |
| **M0** | 下一步 | ✅ **先做 M0：验证三个技术假设 + 搭骨架** | 本文档 v0.2 + `M0-验证报告.md` |

**仍待你拍板**：

| # | 问题 | 我的建议 |
|---|---|---|
| **D6-a** | v1 是否需要守护进程？ | **不需要**，先用无状态 CLI；守护进程留给「DSH 关机也要每天报告」的真实需求 |
| **D1-a** | 是否需要 T3 原始 Shell？ | 需要但**默认关闭**、按目标开启、强制理由 + 建议快照 |
| **D4-a** | 凭据存储：v1 接受「本地加密 vault + 主口令」，还是必须上系统钥匙串？ | v1 用 vault（跨平台一致、无额外依赖），钥匙串 v2 可选 |
| **D6-b** | 要不要把 `dsh-schedule` 加进 profile，让每日报告直接出现在对话里？ | 可以，但会改动 `cordis.patch.yml`；建议先跑 B 方案看够不够用 |
| **D2-a** | 传输层默认后端：`ssh2` 还是 OpenSSH？ | v1 默认 `ssh2`（密码引导唯一可行路径）；本机有 OpenSSH，`native` 作为可选后端保留 |

> 🔎 **一个 M0 得到的额外事实**：本机**已装 OpenSSH 客户端**（`C:\Windows\System32\OpenSSH\ssh.exe`、
> `ssh-keygen.exe`）。这**没有推翻** D2 的结论 —— `ssh.exe` 依然无法非交互接收密码，
> 但那对「生成密钥」等操作有用：M1 可以用 `ssh-keygen` 产密钥，或在 `ssh2` 里用纯 JS 生成。
> 另外 Git for Windows 自带 `bash.exe`，可用来在本机对 `agent/bootstrap.sh` 做语法检查与冒烟测试。

### 15.2 已知风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| 模型选错动作或参数 | 误操作 | plan 前置 + 差分审批 + dry-run 建议 + 危险动作复述主机名 |
| 审批疲劳 | 安全机制被绕过（用户无脑同意） | 风险分级（D5，已拍板 R0/R1 免弹）+ 审批文案突出**影响面**而非命令 |
| 长任务中断后状态不明 | 重复执行/漏执行 | 幂等 check + 远端 run 日志续读 + `unknown` 状态如实呈现（不假装成功） |
| 心跳/探针噪音淹没日志 | 审计不可用 | R0 心跳折叠为小时聚合（§7.4） |
| 非 systemd / 只读根发行版 | 部分动作不可用 | facts 能力声明 + `blocked` 明确原因，不猜测 |
| 归档跨版本 | 导入失败 | schema 版本检查 + 逐级迁移 + 未知字段保留 |
| **动作目录字段拼错导致风险级静默降级** | 本该 R3 的动作以 R1 执行 | ✅ **已消除**：目录加载器拒绝未知字段（`catalog/src/index.js`），有单测 |
| DSH 插件 API 变动 | 插件失配 | M0 已对着类型声明核实并写进 `M0-验证报告.md`；依赖版本据此锁定 |

### 15.3 核实状态（M0 更新）

**已核实 —— 读 DSH 类型声明 + 本机实测**：

| 事项 | 结论 | 证据来源 |
|---|---|---|
| 函数插件契约 | 导出 `name`/`inject`/`apply`，**不得有 default 导出** | `dsh-tool-todo/README.md`；`tools/checks/verify-plugin.mjs` 断言 |
| 工具注册签名 | `ctx.tools.register(definition: ToolDefinition): () => void` | `dsh-tools/lib/types/index.d.ts:603` |
| `ToolDefinition` 必填项 | **`output: { schema, render }` 是必填**；`execute(args, exec)`；可选 `timeoutMs`/`presentCall`/`presentResult`/`isConcurrencySafe` | `dsh-tools/lib/types/index.d.ts:97-172` |
| `exec` 上下文 | `callId`（必有）、`agent?`、`signal`（必有）、`arguments`（冻结） | `dsh-tools/lib/types/index.d.ts:196-283` |
| `ContentBlock` | `{ type:'text', text:string }` 等；`render` 必须返回其数组 | `dsh-llm/lib/types/types.d.ts:39-89` |
| 审批请求字段 | **只有** `agent`(必填)/`toolName`(必填)/`callId?`/`reason?`/`signal?` | `dsh-user-approval/lib/types/index.d.ts:104-125` |
| 审批结果词表 | `allowed-once`(唯一授予)/`rejected`/`cancelled`/`unavailable`；缺失应答器返回 `unavailable` | `dsh-user-approval/lib/types/types.d.ts:23` |
| 审批前置条件 | **必须有打开的回合**；空闲发起会在写入前被拒 | `dsh-user-approval/lib/types/index.d.ts:153-171` |
| 审批策略 | 仅 `ask` / `never`；`setPolicy(agent, policy)` | 同上 :141-152 |
| 渲染意图形状 | `GenericCallView`/`TerminalCallView`/`DiffCallView`；结果侧另有 6 种 | `dsh-tools/lib/types/presentation.d.ts:41,130` |
| 客户端 slot id | `conversation.session.header.actions` 等 20+ 个真实存在；审批 UI 由 composer 承载 | `dsh-client-ui-conversation/.../slots.d.ts:61-324,694` |
| 本地插件挂载 | `--patch <yml>` 叠加层可用；`insert:` 条目 `{id,name,config}` 能被正确合成（实测 exit=0） | `dsh --help`；实跑 `--dump-config` |
| 官方插件安装通道 | `dsh plugin --profile <name> add <package>`（转发给 profile 目录的 pnpm） | `dsh --help` |
| 组合里有哪些服务 | `dsh-user-approval` / `dsh-tools` / `dsh-storage-json` / `cordis-plugin-timer` / `dsh-jobs-local` / `dsh-permission-presets` **均已组合** | 实跑 `--dump-config` 逐项 grep |
| **`dsh-schedule`** | ⚠️ **未组合进 web profile** —— 方案 A 默认不可用 | 同上 |

**仍未核实 —— M1 第一件事**：

- **Loader 是否真能 import 本地插件**：`--dump-config` 只证明**配置树合成成功**，不证明模块被加载。
  验证需要一个真实启动。而启动 `--profile web` 会与你**正在使用的** GUI 争端口，因此这一步需要你点头，
  或另建一个独立 profile（如 `--profile vmprobe-dev`）来跑。
- **插件安装的准确形式**：`name` 用绝对路径 / `link:` / `file:` 哪一种能被 Loader 正确解析（`dump-config` 不做解析）。
- 客户端插件热更新是否必须同时跑 `pnpm run dev:web`（用于 M1 的 UI 开发流程）。
- `ssh2` 在 profile（pnpm workspace）里能否顺利安装（预期可行，未测）。
- `ctx.systemPrompt.section` 的确切签名（M0 已做**守卫 + 明确告警**，缺失时不会崩，但也不会静默假装成功）。

---

## 16. 附：模型侧基础用法提示（`vmprobe_catalog` 返回内容草案）

```markdown
## VMProbe 基础用法

**查看状态**：`vmprobe_status` → 连接状态 + 环境摘要（发行版/负载/磁盘/待更新）
**详细画像**：`vmprobe_facts { target, section }` → os/pkg/hw/net/ssh 分节查询
**可用动作**：`vmprobe_catalog` → 动作清单与参数
**执行动作**：`vmprobe_action { target, action, params, dryRun }`
  - 推荐流程：先 `dryRun: true` 看差分 → 再正式执行
  - 风险级 R1+ 会请求用户审批；被拒不算错误，如实报告即可
  - 返回 `blocked[]` 时不要绕路尝试别的动作，把阻塞原因告诉用户

**常用动作**
| 意图 | 动作 | 风险 |
|---|---|---|
| 更新系统 | `system.update` | R1（含内核→R2）|
| 安装软件 | `pkg.install { packages:[…] }` | R1 |
| 重启服务 | `service.restart { name }` | R1 |
| 配置免密登录 | `ssh.passwordless.enable` | R3 |
| 查看磁盘 | `probe.disk` | R0 |
| 读日志文件 | `file.read { path, tail }` | R0 |
| 上传/下载文件 | `file.push` / `file.pull` | R1 / R0 |
| 重启虚拟机 | `system.reboot` | R3 |

**注意**
- 一次只做一个动作，不要假设上一条已生效——用 `verify` 结果说话
- 改动前若 actions 报告 `snapshotCapable`，建议先提示用户可做快照
- 不确定用哪个动作时，先 `vmprobe_catalog`，不要自行拼 shell 命令
```

---

*文档结束 · 待评审后进入 M0*
