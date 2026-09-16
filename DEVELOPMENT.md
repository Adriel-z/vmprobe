# VMProbe 二次开发手册

> 面向要接续开发这个项目的人（也可能是一段时间后的你）。
> **本文记录两件事**：① 现在做到哪了（带证据）；② 接下来往哪做、怎么做。
>
> 配套文档：`README.md`（安装使用）· `DESIGN.md`（架构与设计决策）· `ISSUES.md`（缺陷台账）
> 代码规模：`packages/**/src` **6469 行** · 单测 **174 项**（含 2308 行测试代码）· 推演探测点 21 个 · SSH 端到端 27 项 · 归档检查 12 项 · 协从端脚本 558 行

---

## 目录

1. [项目定位与边界](#1-项目定位与边界)
2. [代码地图](#2-代码地图)
3. [启动时序](#3-启动时序)
4. [开发进度台账](#4-开发进度台账)
5. [已核实的 DSH 集成事实](#5-已核实的-dsh-集成事实)
6. [扩展指南（5 个 recipe）](#6-扩展指南)
7. [测试与调试](#7-测试与调试)
8. [二次开发硬约束](#8-二次开发硬约束)
9. [已知限制与技术债](#9-已知限制与技术债)
10. [路线图 M1–M5](#10-路线图-m1m5)
11. [单台 → 多台的演进路径](#11-单台--多台的演进路径)

---

## 1. 项目定位与边界

**目标场景：管理一台 Linux 云服务器。** 这个定位决定了几处刻意的简化 —— 二次开发时别把它们当 bug：

| 为"单台"做的简化 | 若要多台需要做什么 |
|---|---|
| UI 走极简路径（状态徽标 + 无目标列表也没关系） | 需要目标列表 / 分组 / 汇总报告 |
| 报告目录 `reports/<targetId>/…` 已按目标分片，但**报告只写当前目标** | 需要跨目标的汇总视图与批量触发 |
| 没有并发调度（同目标动作串行是靠"工具不声明并发安全"隐式达成） | 需要显式的每目标队列与全局并发上限 |
| 存储是单目录 JSON + JSONL，没有索引 | 目标多了需要索引（DSH 自带 `dsh-session-query-sqlite` 可借鉴） |
| 没有"目标凭据轮换/批量录入"的批量流程 | 需要批量凭据管理 UX |

**明确不做的事**（除非需求变化）：

- 不做 Ansible 式的编排 DSL —— 本项目是"探针 + 动作"，不是配置管理引擎。
- 不支持 Windows / macOS 作为**被控端**。
- 不做云端凭据同步；凭据不随归档迁移（设计决策 D4 / §11.4）。
- 不做独立 GUI 安装包；主控端 UI 完全寄生于 DSH Web。

---

## 2. 代码地图

### 2.1 依赖方向（严格单向，改代码时不要打破）

```
catalog ──┐
          ├──► core          （core 不依赖任何项目内模块，也不依赖 DSH）
plugin-host ──► core + catalog
agent/bootstrap.sh           （完全独立，只与主控端通过 stdout JSON 约定通信）
tools/*                      （只读地检查上面这些，不参与运行时）
```

**`core` 零 DSH 依赖**是刻意设计：它能在没有 DSH 的环境里单测、能被将来的 CLI 复用、
也保证"安全策略"不会被宿主框架的实现细节污染。**新增 core 代码时不要 import `@deepseek-ai/*`。**

### 2.2 文件清单与职责

| 文件 | 行数 | 职责 | 关键导出 |
|---|---|---|---|
| `core/src/risk.js` | 143 | **安全核心**：风险分级 R0–R3、审批决策、提权规则 | `Risk` `DEFAULT_POLICY` `decideApproval` `buildApprovalReason` `maxRisk` |
| `core/src/plan.js` | 267 | 计划构建、跨发行版命令解析、**状态指纹 + 有效期**（TOCTOU） | `buildPlan` `resolveCommands` `checkFingerprint` `checkPlanFreshness` `PLAN_TTL_MS` |
| `core/src/params.js` | 108 | 动作参数校验、默认值归一化、**未接线参数检出** | `validateParams` `normalizeParams` `findUnwiredParams` |
| `core/src/audit.js` | 177 | 哈希链：规范化 JSON、链式追加、篡改校验、内存窗口 | `chainRecord` `verifyChain` `createAuditLog` `canonicalJson` `sha256Hex` |
| `core/src/store.js` | 198 | 原子写 JSON、**机制化拒密**、id 安全校验、目标记录构造 | `openStore` `makeTarget` `assertSecretFree` `isSecretKeyName` `assertSafeId` |
| `core/src/redact.js` | 183 | **统一脱敏**：私钥/JWT/URL 凭据/命令行凭据/Bearer/kv 形式 | `redactText` `redactDeep` `createRedactor` |
| `core/src/reports.js` | 247 | 日报文件子系统：日键、路径、原子写、缺天、保留策略、趋势 | `writeReport` `readDay` `listDays` `findGaps` `pruneReports` `buildTrend` `reportPath` |
| `core/src/report-builder.js` | 100 | 报告内容：指标抽取（缺失记 null）、环境摘要、异常判定 | `extractMetrics` `buildDailyReport` `reportNeedsAttention` |
| `core/src/index.js` | 53 | core 的统一出口（**新模块记得在这里 re-export**） | — |
| `catalog/src/index.js` | 160 | 动作目录加载器：**严格校验**（未知字段即拒载；argv 元素形状与参数引用也校验） | `loadCatalog` `validateAction` `listCatalog` |
| `catalog/actions/*.json` | — | 4 个内置动作（含 controller 侧的 3 个） | — |
| **`transport/src/keys.js`** | 130 | OpenSSH 密钥编码（公钥行 + 私钥容器 + 指纹），**自研**（ssh2 不接受 PKCS8 ed25519） | `generateKeypair` `opensshPublicKeyLine` `opensshPrivateKeyFile` `publicKeyFingerprint` |
| **`transport/src/ssh.js`** | 560 | SSH 会话管理：连接复用、keepalive、主机密钥三态校验、exec（含 argv 引用与 idempotent 超时）、stdin/文件投递、`verifyKeyLogin` / `verifyPasswordLogin` | `createSshTransport` `shQuote` `buildCommand` `HostKey*Error` |
| **`transport/src/passwordless.js`** | 300 | 免密登录事务（启用 + 撤销），**核心不变式：任何时刻至少一条可用连接路径** | `enablePasswordless` `disablePasswordless` `PasswordlessError` |
| `plugin-host/src/index.js` | 390 | DSH 插件入口：`name`/`inject`/`apply` + 凭据适配 + 传输层装配 + controllerHandlers + 加载台账 + 定时器 | `name` `inject` `apply` `DEFAULT_STORAGE_DIR` `DEFAULT_AGENT_SCRIPT` |
| **`plugin-host/src/services.js`** | 78 | **可选服务的唯一读取入口**（`ctx.get` 而非 `ctx.approval`；I6） | `optionalService` `resolveApproval` `approvalAvailable` `resolveCredentials` |
| `plugin-host/src/tools.js` | 775 | 6 个 `ToolDefinition`、统一错误脱敏出口、凭据状态查询（只看"是否已配置"） | `createTools` `USAGE_HINT` |
| `plugin-host/src/engine.js` | 700 | 引擎：目标 / 计划 / 执行分发 / 审计落盘与轮转 / 报告盖章 / 新鲜度校验 / facts 落盘 / 指纹固定 / 认证切换 | `createEngine` `PlanStaleError` `NotImplementedError` |
| `plugin-host/src/scheduler.js` | 113 | 每日报告调度器（tick + 幂等 + 单飞） | `startDailyReportScheduler` `normalizeAtUtc` |
| `plugin-host/cordis.patch.yml` | — | 包自带的挂载声明（`dsh.bundle` 指向它） | — |
| `agent/bootstrap.sh` | 620 | 协从端：facts 采集 / 安装 / 卸载（POSIX sh，无解释器依赖；**经 SSH stdin 投递即可运行**） | — |
| `tools/doctor.mjs` | — | 离线预检（凭据 / overlay / bundles 一致性 / id 冲突 / 活实例） | — |
| `tools/fix-credentials.mjs` | — | 凭据 YAML 修复（备份 + 逐值 sha256 保真 + 原子替换） | — |
| `tools/vmprobe-cred.mjs` | — | **凭据录入**（不回显 + 二次确认 + 原子写；从不输出任何值） | — |
| `tools/checks/*` | — | 六项检查：契约（含**真实 cordis 加载**）/ 推演 / **SSH 端到端** / 转义 / 安装守卫 / 文档一致性（+ bash 定位器） | — |

---

## 3. 启动时序

理解这条链路对改代码很重要（尤其是"为什么定时器要用 `ctx.inject`"）：

```
DSH 启动
 └─ 合成 profile：bundles（含 @vmprobe/plugin-host 的 patch）→ cordis.patch.yml → --patch 叠加层
     └─ 逐条 apply loader entry；**任何一条失败 → 整棵树失败 → 进程 exit 1**
         └─ import '@vmprobe/plugin-host' → 取 name / inject / apply
             └─ 等 inject = ['tools','approval'] 就绪
                 └─ apply(ctx, config)
                     ├─ 建凭据适配器（**延迟到调用时才读 ctx.credentials**）
                     ├─ createSshTransport()   传输层（配置里显式给 transport 则跳过）
                     ├─ createEngine()         存储 + 目录 + 传输层 + controllerHandlers
                     ├─ createTools()  → ctx.tools.register × 6   （每个都必须带 output）
                     ├─ ledger('load')         落加载台账
                     ├─ ctx.inject(['timer'], cb)  ← 不阻塞 apply，等 timer 就绪才跑
                     │    └─ startDailyReportScheduler() → ctx.interval(tick, 60s)
                     │         └─ ledger('scheduler.started')
                     └─ ctx.on('dispose')      停定时器 + 注销工具

一次动作执行（以 system.update 为例）
 plan：engine.planAction
   ├─ factsFor(target)         内存 → 磁盘回退（拿到发行版）
   ├─ transport.check(action)  只读探测 → 状态指纹的输入
   ├─ resolveCommands(...)     按发行版选分支 + **把参数接进 argv**（并回报哪些参数被消费）
   └─ buildPlan → 风险级（含内核→R2）/ 阻断项 / 有效期
 审批：仅 R2/R3；controller 侧动作先在 canApply 里确认 handler/传输层存在
 执行：engine.applyPlan
   ├─ verifyPlanFresh（再校验一次指纹+有效期，防 TOCTOU）
   ├─ side=agent      → transport.apply → exec 每条 argv（逐个安全引用）
   └─ side=controller → 本地 handler（probe.facts / auth.*）
 留痕：engine.record(...) → 脱敏 → 哈希链 → 落盘（按大小轮转）
```

**两处只能靠"启动一次"才能发现的失败**（`--dump-config` 查不出来，它不做 import）：

1. `name` 解析不了（裸路径 / 目录 / 包名不可达）。
2. **entry id 重复**（overlay 与已安装 bundle 同 id）。

---

## 4. 开发进度台账

### 4.1 已完成并有证据

| 模块 | 状态 | 证据 |
|---|---|---|
| **SSH 传输层（ssh2）** | ✅ 完成 | `tools/checks/ssh-transport.mjs` 25 项：真实握手、主机密钥三态（首连固定/严格比对/不符拒绝）、exec（stdout/stderr/退出码）、**注入防御**、stdin 投递、超时、连接复用、文件推送往返、心跳三态（成功 / 干净断开 / 静默死亡） |
| **OpenSSH 密钥编码（自研）** | ✅ 完成 | **三个独立验证器**：ssh2 `parseKey` 解析、**真实 `ssh-keygen -y` 导出同一公钥**、真实 publickey 认证握手；指纹与 `ssh-keygen -lf` 格式一致 |
| **免密登录事务（启用 + 撤销）** | ✅ 完成 | 真实协议 + 真实 authorized_keys 闭环：写 key → **另开连接验证** → 才切断旧连接 → 密钥重连；**失败注入测试**证明回滚干净且旧连接仍可用；幂等（第二次不重复追加）；公钥认证被禁用时**什么都不动** |
| **动作参数接线（按发行版）** | ✅ 完成 | `param-wiring.test.js` 12 项 + 目录加载器校验（未知字段/空 `$when.argv`/引用未声明参数都拒载）；机制是"接线由 argv 用法推导"，作者无法谎称已接线 |
| **掩码凭据录入** | ✅ 完成 | `tools/vmprobe-cred.mjs`：交互式不回显 + 二次确认 + 原子写 + 写前 YAML 校验 + 环境变量遮蔽检测；**从不输出任何凭据值**（连长度都不打） |
| **facts 采集与落盘** | ✅ 完成 | 引导脚本经 **SSH stdin 投递**（`sh -s -- --check`）零安装采集；落盘 `<storageDir>/facts/<id>.json`，`factsFor()` 内存→磁盘回退（重启不丢发行版映射） |
| **controller 侧动作处理器** | ✅ 完成 | `probe.facts` / `auth.enablePasswordless` / `auth.passwordless.disable` 三个 handler 接进插件 |
| **`vmprobe_facts` 工具** | ✅ 完成 | 第 6 个工具；契约测试含"用 DSH 自己的 `assertSupportedJsonSchema` 验 schema 子集" |
| 风险分级与审批决策 | ✅ 完成 | `risk.test.js` 10 项：R0/R1 免弹、R2/R3 必弹、prod 提权、内核提权、`never` 策略 fail-closed、未知级抛错 |
| 计划构建 + 跨发行版分流 | ✅ 完成 | `catalog.test.js` 14 项：5 大发行版系 argv 解析、未知字段拒载、`dynamic` 必须有 check、argv 元素形状校验 |
| 计划新鲜度（TOCTOU） | ✅ 完成 | `freshness.test.js` 9 项：指纹对决策字段敏感 / 忽略易变字段、过期、环境变化、无法验证即 fail-closed |
| 参数校验与未接线阻断 | ✅ 完成 | `params.test.js` 9 项：类型/enum/未知键/必填（两种写法）+ 默认值归一化 |
| plan 加固（side / 空 argv / 参数） | ✅ 完成 | `plan-hardening.test.js` 7 项 |
| 审计哈希链 | ✅ 完成 | `audit.test.js` 10 项：键序无关、篡改断链、删条断链、自洽伪造仍被检出、`chainRecord` 不改入参 |
| 拒密与 id 安全 | ✅ 完成 | `store.test.js` 5 项：键名/私钥值拦截、`authRef` 不受影响、原子写、临时文件不残留 |
| 统一脱敏 | ✅ 完成 | `redact.test.js` 18 项：JSON/带引号/裸值三种 kv 形式、复合名、Bearer、`curl -u`、URL 凭据、幂等、不误伤 `mypassword` |
| 日报文件子系统 | ✅ 完成 | `reports.test.js` 12 项：命名合法性、字典序=时间序、同日追加、跨日独立、缺天、不可达落盘、保留策略、schema 保护 |
| 报告内容与趋势 | ✅ 完成 | `report-builder.test.js` 9 项 |
| 引擎：审计落盘/轮转、报告盖章、写锁、TOCTOU 双检、facts 落盘、指纹固定、认证切换 | ✅ 完成 | `simulate-faults.mjs` 的 F8/F9/I6/I7/I11 探测点 |
| 每日报告调度器 | ✅ 完成 | 探测点 I10 + 真机 `scheduler.started` |
| **verify 真正执行（M2-①）** | ✅ 完成 | 目录声明 `verify { probe, expect, maxWaitMs }`；apply 之后**真的再探测一次**并给出 `true/false/null` 三态；`m2-engine.test.js` 8 项 + 真实 SSH 端到端 4 种情形（达标 / 未达标 / 探测未实现 / 预演跳过） |
| **运行记录落盘（M2-②）** | ✅ 完成 | `runs/<runId>.log`（计划 + 逐条命令 + exit + stdout/stderr + 校验结论）；写盘前过同一套 redactor；超限截断并标注；`runId` 形状校验挡路径穿越；审计只留 `{path, sha256, bytes}`，`verifyRunSeal()` 可核对篡改 |
| **取消贯通（M2-③）** | ✅ 完成 | `exec.signal` 贯通到 SSH 通道（先 TERM、3s 后硬关）；`action.cancelled` 与失败分开记；**真实 SSH 验证**：中断 412ms 返回、远端命令未跑完（标记文件 ABSENT）、连接仍可用；工具自此**声明 `timeoutMs`** |
| **审批策略真正生效（技术债 #1）** | ✅ 完成 | core 的 `decideApproval` 现在同时看 `autoAllowUpTo` 与 `alwaysAskFrom`（默认行为不变）；插件把策略透传进 `buildPlan`；启动写 `config.effective` 审计；未知/非法/更宽松的配置键**三重可见**（logger + 台账 + `vmprobe_status`） |
| **日报保留策略接定时器（技术债 #5）** | ✅ 完成 | 每天生成后顺带清理一次，幂等键 = UTC 日键；清理失败不影响生成但明确告警 |
| **DSH 运行时依赖可移植解析（技术债 #10）** | ✅ 完成 | 新增 `tools/lib/dsh-runtime.mjs`：按 `DSH_RUNTIME_ROOT` → `dsh` 可执行文件 → Node 前缀逐层探测（含 DSH 自身嵌套依赖）；**四个工具里写死的本机绝对路径全部消除** |
| **心跳保活与连接健康观测** | ✅ 完成 | `scheduler.js` 的 `startTransportHeartbeat`：60s 一次、5s 超时、**只探活跃会话**（绝不主动拉连接，否则"心跳"会掩盖"其实早就断了"）；`vmprobe_status` 显示延迟/失败次数/最初失败原因；审计只在**状态变化**时落一条 |
| **I5 决策落地：approval 改为可选注入** | ✅ 完成 | `inject=['tools']`；缺审批时插件照常加载、R0/R1 照常执行、**R2/R3 一律拒绝且 `transport.apply` 调用次数为 0**；日志+台账+状态三重可见（DESIGN D14） |
| **审计链 HMAC（M5 部分）** | ✅ 完成 | 逐条 `algo`/`keyId`、禁止降级、换密钥≠被篡改、旧链完全兼容；12 项单测；启动时把"实际生效的密钥指纹与来源"写进审计（DESIGN D15） |
| **归档与迁移（M3）** | ✅ 完成 | `.vmpz` = 标准 zip（自研容器 ~200 行，零依赖）+ 清单 sha256 + schema 版本校验 + 脱敏档位 + 私钥强制加密（scrypt+AES-GCM）+ 导入差异预览与备份；**审计密钥与私钥永不入档**；15 项单测 + **PowerShell `Expand-Archive` 外部交叉验证** |
| **运行日志 `logs/run.jsonl`（技术债 #13）** | ✅ 完成 | 与审计分工：带 `level`、**不入哈希链**、只留一代历史（DESIGN D16）；4 项单测含"不得每次写入都轮转"的回归 |
| **认证切换记住原凭据** | ✅ 完成 | `switchTargetAuth` 会记 `previousAuthRef`（仅当原来是口令/密码时），否则撤销免密会因为"口令 ref 已被覆盖"而**拒绝执行**（fail-closed 但不可用）；往返测试：启用免密 → 撤销免密 → 仅用口令重新连上 |
| 协从端 facts 采集（含 load/hw/包状态） | ✅ 完成 | `--check` 输出合法 JSON；`pkg.upgradable`/`securityUpgradable`/`kernelUpgradePending` 一次查询产出；缺失记 null |
| 协从端安装完整性守卫 | ✅ 完成 | `check-install-guard.sh` 8 项 |
| 不可信输入转义 | ✅ 完成 | `check-escape.sh` |
| **真机加载验证** | ✅ 完成 | 真实 profile（无 `--patch`）启动 → 台账 `event:"load"`（6 工具 / 4 动作 / `transport:"detached"`）+ `scheduler.started` |
| 环境预检与凭据修复工具 | ✅ 完成 | `doctor.mjs`（含 bundles 一致性、overlay id 冲突）、`fix-credentials.mjs`（逐值 sha256 保真） |

### 4.2 未开始（见 §10 路线图）

| 模块 | 状态 | 说明 |
|---|---|---|
| 快照 / 回滚 | ⛔ 未开始 | `rollback.strategy` 与 `snapshotCapable` 已采集，但没有落地动作 |
| 协从端本地审计 + 双端交叉核对 | ⛔ 未开始 | 需要 agent 二进制（Go）与协议 || 归档导入导出 | ⛔ 未开始 | 设计 §11（M3） |
| T2 白名单命令 / T3 原始 shell | ⛔ 未开始 | 设计 D1 的档位，默认关闭；`allowRawShell` 配置键会被**明确拒绝并告警**，不静默接受 |
| 纯 JS 的 `docker exec` / 本地传输后端 | ⛔ 未开始 | 用于"在同一台机器上跑"或容器场景，测试也更好写 |
| 客户端 UI 插件（浏览器侧） | ⛔ **受环境阻塞**（见 §9 #11） | 本机发行版里**没有客户端打包器**、客户端 peer 包也**未发布到 npm**；宿主侧已先把同样的信息做进对话（结果卡片 + 状态里的配置警告） |
| 协从端守护进程 / 本地定时（M4） | ⛔ **刻意推迟** | 见 §10 M4：它的价值全在"Linux 上的 sshd/systemd/unix socket 行为"，而这些在本机**无法验证**（没有 Linux 目标）。按"能验证才敢说已实现"的纪律，宁可不写也不写个只能半验的守护进程 |

---

## 5. 已核实的 DSH 集成事实

**这一节的价值在于：以下每一条都是实测/读类型声明得到的，不是猜的。** 照抄即可，别再踩一遍。

### 5.1 类型形状（读 `.d.ts` 得到，附来源）

```js
// ① 函数插件契约（来源：dsh-tool-todo/README.md）
export const name = 'vmprobe'
export const inject = ['tools']                  // **只放"缺了就什么也做不了"的服务**
// ★ approval / credentials / systemPrompt / timer **都不在这里** —— 可选服务缺失不该让整棵树失败
// ★ 绝不能有 default 导出 —— Loader 的 unwrapExports 会折叠模块并丢掉 inject
export function apply(ctx, config = {}) { }      // 同步即可（不要依赖 await 异步 apply）

// ② 工具注册（来源：dsh-tools/lib/types/index.d.ts:603）
ctx.tools.register(definition: ToolDefinition): () => void

// ③ ToolDefinition（来源：同上 97-172）—— output 是**必填**
{
  name, description,
  parameters,                    // Record<string, unknown>；规范形式是 JSON Schema
  output: {                      // ★ 每轮请求的前缀开销来源
    schema: { type:'object', properties:{…}, required:[…] },
    render: (args, value) => [{ type: 'text', text: '…' }],   // → ContentBlock[]
  },
  execute(args, exec),           // exec: { callId, agent?, signal, arguments }
  timeoutMs?,                    // ★ 声明它 = 断言"能把 exec.signal 传到静止"；做不到就别声明
  presentCall?(args),            // 纯函数，会话重放时也会被调用
  presentResult?(args, result),
  isConcurrencySafe?(args),      // 只有 true 才加入并行组；不声明 = 独占（形成排序屏障）
}

// ④ ContentBlock（来源：dsh-llm/lib/types/types.d.ts:39-89）
{ type: 'text', text: string }

// ⑤ 审批（来源：dsh-user-approval/lib/types/index.d.ts:104-125）
//     只有五个字段，**没有承载富文本的通道** —— 所以富计划必须走工具结果 + presentCall
const approval = ctx.get('approval')             // ★ 不是 ctx.approval！见 ⑧
approval?.request({ agent, toolName, callId?, reason?, signal? })
  → Promise<'allowed-once' | 'rejected' | 'cancelled' | 'unavailable'>
// ★ 只有 allowed-once 是授予；缺失/抛异常的应答器返回 unavailable → 必须 fail-closed
// ★ 要求当前有**打开的回合**：空闲时发起会被拒 → 定时任务无法申请审批（只能做 R0/R1）

// ⑥ 渲染意图（来源：dsh-tools/lib/types/presentation.d.ts:41,130）
{ card:'generic', title, kind?: 'read'|'edit'|'delete'|'move'|'search'|'execute'|'fetch'|'other',
  rawInput?, content?, locations? }          // ToolCallView
{ card:'generic', title?, content? }         // ToolResultView（另有 terminal/diff/search/read/web）
{ card:'diff', title, diffs:[{path, oldText|null, newText}] }   // 将来渲染 sshd_config 改动可用

// ⑦ 可选依赖的动态注入（来源：cordis registry.d.ts:111）
ctx.inject(['timer'], (childCtx) => { … })   // 依赖就绪时执行；缺失则永不执行，**不阻塞插件加载**

// ⑧ **读可选服务**（来源：cordis reflect.ts 的 `get` 文档 + DSH 自己的用法）
ctx.get('approval')        // → 服务实例，或 undefined（无注入要求）
ctx.approval               // ✖ 不要这么写：服务"已声明但本 fiber 未注入"时**抛异常**
                           //   `Error: cannot get property "approval" without inject`
// ★ 为什么：cordis 的 ctx 是 Proxy，只有"把名字放进 inject"的 fiber 才会把服务快照进
//   fiber.store（Fiber.store 的注释原话：*snapshot of **required** service implementations*）。
//   DSH 自己一律用 ctx.get：dsh-tools 的 serviceAsk、dsh-tool-bash / -fs / -pwsh、
//   dsh-subagent、dsh-host-apiproxy 都是这个写法。
// ★ 本项目的收敛点：`plugin-host/src/services.js`（optionalService / approvalAvailable / resolveCredentials）
```

### 5.2 十九个实测出来的坑（每条都真的踩过）

| # | 坑 | 现象 / 修法 |
|---|---|---|
| 1 | **`--dump-config` 不验证挂载** | 它只合成配置树、**不做 import**，所以错误路径/错误形式在它眼里全都"成功"。要验证必须真的启动一次 |
| 2 | **Windows 上 `name` 不能用裸绝对路径** | `Only URLs with a scheme in: file, data, and node are supported… Received protocol 'c:'` → 用 `file:///C:/…` 或包名 |
| 3 | **`name` 不能指向目录** | `Directory import … ERR_UNSUPPORTED_DIR_IMPORT` → 指向入口文件，或改用包名 |
| 4 | **`--help` 在加载插件树之前就短路** | 用 `--help` 启动"成功"**不能**作为加载证据。差分实验：把 `name` 换成不存在的路径，`--help` 同样 exit 0（详见 `tools/overlay-bogus.yml`） |
| 5 | **容器依赖顺序会静默吃掉定时器** | 没 inject `timer` 就调 `ctx.interval` → 那一刻服务还没就绪 → **定时器从未注册且无任何报错**。改用 `ctx.inject(['timer'], cb)` |
| 6 | **重复 entry id 致命** | 插件作为 bundle 装入后再用同 id 的 overlay → `duplicate loader entry id` → **整棵树加载失败 exit 1**。`doctor` 会预警 |
| 7 | **bundles 与 dependencies 必须成对** | `dsh plugin add` 会自动同时加两处；卸载只删依赖会因"解析不到 bundle"而启动失败 |
| 8 | **`ctx.logger` 不可靠** | 输出既不一定进 stdout、也不一定进 DSH 日志文件 → 因此有了加载台账 `loads.jsonl`。**排查"加载了没有"只看台账** |
| 9 | **`output.schema` 只支持 JSON Schema 子集，写错会让整棵树加载失败** | DSH 只接受**单个标量 `type`**（可空要写 `oneOf: [{type:'object'},{type:'null'}]`）、`properties`/`required`/`additionalProperties`、`items`、标量 `enum`/`const`、**恰好一个分支的 `oneOf`**。**不支持 `type: ['string','null']`** —— 实测启动即报 `unsupported JSON schema: ... type must be a single type string`，整棵插件树加载不出来。**对策**：契约脚本现在直接用宿主的 `assertSupportedJsonSchema` / `assertObjectJsonSchema` / `validateJsonSchemaValue` 校验，不用启动就能拦住 |
| 10 | **Windows 上 Node 与 MSYS 的路径视角会分裂** | `os.tmpdir()` 在本机返回 `/tmp`（优先读 `TMPDIR`），而 MSYS 的 `/tmp` 是**另一个目录** → 一边写 `C:\tmp\...`、一边读 Git 的 `/tmp/...`，表现为"文件写了却读不到"。规则：**给 bash 用的环境变量要 MSYS 形式（`/c/...`，用 `cygpath -u` 换算）；`spawn` 的 `cwd` 要 Windows 形式**（给 `/c/...` 会 ENOENT） |
| 11 | **不要把一个 `printf` 和后续命令拼进同一条命令** | 写免密事务的环境探测时踩过：`printf "%s\n%s\n%s\n%s" "$HOME" … test -w "$HOME" && …` 会把 `test`、`-w` 当成 printf 的参数，输出的第 4 行变成字面量 `test` 而不是 `writable`。**探针脚本必须分行** |
| 12 | **`facts.os.idLike` 是数组，不是字符串** | os-release 里 `ID_LIKE` 是空格分隔字符串，但语义是列表。曾有一方按数组用、另一方发字符串 → `idLike.join is not a function`。现在：agent 发**数组**，`resolveCommands` 与引擎都做容错（两种都接受） |
| 13 | **同一条会话上的"第二次探测"会掩盖第一次的失败** | 写心跳死亡测试时踩过：先直接调 `transport.heartbeat` 断言它报 `error`，再用同一会话驱动引擎、期望引擎也看到 `error` —— 但 transport 在**第一次失败时已把会话标成 `detached`**，于是引擎看到的是 `no-session`，断言的是"第二个观察者的第二次探测"而非那次失败。**规则**：要断言两层的两种行为，就要有**两条独立会话**，且每个断言都在"会话仍是 connected"时由对应那层探测。顺带修掉一个真缺陷：失败原因要单独记住，否则第二次探测后"它为什么掉了"就答不上来（见 §9 #13） |
| 14 | **别用自己写的桩去"验证"行为** | 恢复路径最初想用假 client（`exec: (cmd, cb) => cb(null, {stdout…})`）来测，但真 transport 期望的是**流**而非字符串 → 那只是在验证桩写得对不对。**规则**：桩只能用来制造**失败**（注入错误），成功路径一律走真实协议 |
| 15 | **同一个概念有两个"形状"，混用不会立刻报错** | `harnessTarget()` 产出的是**已完成规范化**的目标（`authRef: {kind, ref}`），而 `engine.addTarget()` 要的是**扁平输入**（`authRef: '引用名'`）。两者混用时 `makeTarget` 把 ref 又包了一层 —— 在"忽略参数"的凭据解析器下**照样能连上**，直到某个严格解析器才炸，报错还是"凭据 `[object Object]` 尚未配置"。**规则**：边界上提供两个**名字不同**的构造器（`harnessTarget` / `harnessTargetInput`），并且让 `makeTarget` 直接拒绝对象型 `authRef` |
| 16 | **`timeoutMs: null` 会让整棵插件树加载失败** | `tools.register` 的校验是"定义了就必须是正有限数"：`null !== undefined` → 抛 `TypeError`。当时我正打算用一个 getter 返回 `null` 表示"暂时不声明"—— 那等价于**把 N4 那类致命错误再写一遍**。**规则**：可选字段要么**不出现**（`undefined`），要么是合法值；别用 `null` 表达"没有" |
| 17 | **可选字段"缺失"与"显式为 null"是两种语义** | 校验结论 `satisfied` 一开始在"探测未实现"分支里**整个不返回**，于是调用方拿到 `undefined`。契约上它只有 `true/false/null` 三态，**字段必须永远存在** —— 缺字段会诱使别人写 `if (verify.satisfied)`，把"未判定"当成"否"或"是" |
| 18 | **可选服务不能"直接读"—— cordis 的 ctx 是 Proxy，读未注入的服务名会抛异常** | I5 决策（把 `approval` 从 inject 里拿掉）**落地当天就把 DSH 弄成起不来了**：`apply()` 里那句 `ctx.approval && …` 抛 `cannot get property "approval" without inject` → 那条 entry 失败 → **整棵树加载失败**。写成 `undefined` 心理模型（JS 习惯）在这里是错的：只有 `inject` 里的服务才会被快照进 `fiber.store`。**修法**：一律经 `ctx.get(name)` 读（DSH 自己就这么写），本项目收敛在 `plugin-host/src/services.js`。**更重要的教训**：当时的六项检查全绿 —— 因为它们用的 ctx 是**裸对象**，读不存在的字段只会得到 `undefined`，正好把错误假设"验证"了一遍。现在契约检查里有真实 cordis 起的最小插件树（兄弟 entry 提供服务、VMProbe 未注入），以及"旧写法必须抛"的探测点 |
| 19 | **`systemPrompt.section()` 的签名也只能靠读类型，别靠猜** | 原来写的是 `{ id, title, content }` —— 而 `PromptSection`（dsh-system-prompt/lib/types/index.d.ts:47）要的是 `{ name, order, text }`，且 `order` 非有限数直接抛 `TypeError`。三个字段**全错**，异常被本段 `try/catch` 吞成一条"宿主不支持"的告警 → 提示**从未注入**过，而日志看起来像环境问题。**修法**：按类型改对；契约检查里加了"注册参数形状"断言 |
| 20 | **一条 entry 抛错就能让宿主打不开 —— 所以插件的 `apply()` 必须是"绝不抛"的壳** | 坑 18 修的是"**怎么读**服务"，没管"**万一还是抛了**怎么办"：cordis 里 `apply()` 抛 = 那条 entry 失败 = **整棵插件树加载不出来** → `dsh web` 直接 `exited with code 1`（本项目被这个形态咬过两次：非法 YAML 的 `.credentials.yaml`、I5 当天的 `ctx.approval`）。**修法**：`index.js` 导出的是兜底壳 `apply()`，真实现在**不导出**的 `applyPlugin()`；异常记进 `logger.error` / `stderr` / 台账 `apply.failed` 后吞掉，只有 `config.strict === true` 时照旧抛（开发期要响亮）。**验证方法值得抄**：用 `--patch` 注入一次"必然失败的加载"（`storageDir` 指向"父路径是文件"的位置 → `mkdirSync` 必抛），跑两次 `dsh web` —— `strict: true` 复刻修复前（`plugin tree failed to load` + exit 1），默认则**照常起来并监听端口、HTTP 200**。⚠️ `--patch` 是**根命令**开关，要写在 `--profile web` 之后、app 自己的 `--no-open/--port` **之前**；位置写错只会得到 `error: unknown option '--patch'`（看起来像"这个版本不支持"） |

**另外两条部署要点**：

- **profile 依赖必须用 pnpm 的 `link:`**。`file:` 是版本化拷贝，`add` 后源码改动不刷新
  （会直接说 "Already up to date"），profile 静默跑旧代码。
- **任何一条 loader entry 失败都会让整棵树失败**。实测：`.credentials.yaml` 的一处 YAML 语法错
  （两行手写标注用了**全角冒号**）就让 DSH 再也起不来。→ 动手前先跑 `doctor`。

### 5.3 客户端插件 slot（已核实存在，M1 用）

`dsh-client-ui-conversation/lib/types/client/contract/slots.d.ts` 里真实存在：
`conversation.session.header.actions`、`conversation.session.header.utilities`、
`conversation.details.tool`、`conversation.chat.node`、`conversation.chat.commandview`、
`conversation.chat.turnTail`、`conversation.view`、`conversation.composer`、
`conversation.input.{left,right,plan,dock}`、`conversation.hero.*`。

注意 `conversation.composer` 已承载**审批提示 UI**（`ApprovalComposerProps`）——
审批弹窗由 DSH 现有组件渲染，**我们不需要自建审批界面**。

### 5.4 Web 组合里有哪些服务（实测 grep 结果）

| 服务 | 是否在 web 组合中 |
|---|---|
| `dsh-tools` / `dsh-user-approval` | ✅ |
| `dsh-storage-json` / `dsh-jobs-local` / `dsh-permission-presets` | ✅ |
| `cordis-plugin-timer` | ✅（定时日报依赖它） |
| **`dsh-schedule`** | ❌ **未组合** —— 所以"会话内定时提醒"默认不可用 |

---

## 6. 扩展指南

### R1 —— 新增一个动作（最常用，且**不需要改插件**）

**步骤**

1. 在 `packages/catalog/actions/` 加一个 JSON。照抄这个模板：

```jsonc
{
  "id": "service.restart",              // 小写点分；加载器会校验格式
  "version": 1,
  "side": "agent",                      // agent=远端执行 | controller=主控端本地
  "title": { "zh": "重启服务" },         // zh 必填
  "summary": "重启指定服务并验证其处于 active",
  "risk": "R1",                         // R0|R1|R2|R3|dynamic（dynamic 必须声明 check）
  "params": {
    "type": "object",
    "properties": { "name": { "type": "string", "required": true } },
    "additionalProperties": false
  },
  "wiredParams": [],                    // ★ 参数真正被消费后才填这里（见下方警告）
  "requires": { "root": true, "distros": [], "binaries": ["systemctl"] },
  "idempotent": true,
  "timeoutMs": 60000,
  "check": { "probe": "service.active" },
  "apply": {
    "default":  { "cmd": [["systemctl", "restart", "nginx"]] },
    "openrc":   { "cmd": [["rc-service", "nginx", "restart"]] }   // 按 init 分流的示例
  },
  "verify": { "probe": "service.active", "maxWaitMs": 5000 },
  "rollback": { "strategy": "none" },
  "notes": ["重启会短暂中断服务"]
}
```

2. **`side: "controller"` 的动作要有 `handler`，不能有 `cmd`**（加载器强制）：

```jsonc
{ "id": "ssh.passwordless.enable", "side": "controller",
  "apply": { "default": { "handler": "auth.enablePasswordless" } } }
```

3. 跑检查。**注意：加动作会打破两处"恰好 3 个动作"的断言**，一起改掉：

| 位置 | 断言 |
|---|---|
| `packages/core/test/catalog.test.js` | `listCatalog` 的 id 列表、`has('…')` |
| `tools/checks/verify-plugin.mjs` | `vmprobe_catalog 返回 3 个动作` |

> **⚠️ 最大的坑：参数目前不会进入 argv。**
> `resolveCommands()` 只按发行版选分支，**不做参数替换**。所以：
> - 目录里声明了 `params` 只是"能被校验"；真正让它生效需要扩展 `resolveCommands`（见 §10 M1-②）。
> - 在它生效之前，**`wiredParams` 必须留空** —— 否则你声明"已接线"，用户传了参数却毫无效果，
>   就成了"谎报行为"（这正是缺陷 F2 的形态）。留空时非默认参数会被 fail-closed 阻断，是安全的。

**验证方法**：`npm run test` + `npm run check:plugin`。

---

### R2 —— 新增一个工具

**先问自己：真的需要新工具吗？** 每个工具的 schema 都是每轮请求的固定前缀开销，
而且工具越多模型越容易选错。**能变成"动作"的，就不要变成工具。**

确需新增时，在 `packages/plugin-host/src/tools.js` 的 `rawTools` 数组里加：

```js
{
  name: 'vmprobe_example',
  description: '一句话说清"什么时候该用它"。模型靠这句话决定是否调用，写具体。',
  parameters: {
    type: 'object',
    properties: { target: { type: 'string', description: '目标 id 或显示名' } },
    required: ['target'],
    additionalProperties: false,        // DSH 的理念：开放性必须显式声明
  },
  output: {                             // ★ 必填，否则注册无效
    schema: { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'] },
    render: (_args, value) => [{ type: 'text', text: value.ok ? '成功' : '失败' }],
  },
  presentCall: (args) => ({ card: 'generic', title: `示例 → ${args?.target}`, kind: 'read' }),
  isConcurrencySafe: () => true,        // 只读工具才声明；写操作不要声明（保持独占）
  async execute(args, exec) {
    engine.record('example.run', { targetId: args?.target });   // 审计自动脱敏
    return { ok: true };
  },
}
```

**自动获得的行为**（不用你写）：

- 错误脱敏 —— `createTools()` 把所有工具包了一层 `guarded()`，抛出的错误先过 `redactText` 再出。
  这是刻意的单点设计：不可能"漏掉某个工具"。
- 审计脱敏 —— `engine.record()` 写入前会 `redactDeep` 并附加 `redactedPaths`。

**自己必须做的**：

- `output.render` 的入参 `value` **保证符合 `output.schema`**；不要写"防御性默认值"来掩盖 schema 漂移，
  但也不要假设调用方会传空值（`render({}, {})` 崩溃是正常的，因为契约不允许空值）。
- 若声明 `timeoutMs`，**必须**观察 `exec.signal` 并能在超时后到达静止。做不到就别声明（缺陷 F4 就是这么来的）。
- 高风险操作走 `ctx.approval.request()`，并且在**能力检查之后**才申请（别为做不到的事占用用户注意力）。

**验证**：在 `tools/checks/verify-plugin.mjs` 里补断言（它会遍历所有工具校验 `name/description/parameters/output/render/presentCall` 的形状）。

---

### R3 —— 接入 SSH 传输层（M1 主线，**这是当前最关键的一步**）

**引擎只要求这个接口**：

```js
const transport = {
  /** 只读探测当前状态。返回值会参与"计划新鲜度"判定。 */
  async check(action, target, facts) {
    // ★ 必须带 probed: true —— 否则指纹为 null，计划会被判为"无法验证"而 fail-closed 阻断
    // ★ 只放"影响决策"的字段；时间复杂度稳定；**不要放时间戳**（会让计划永远过期）
    return { probed: true, count: 12, sizeBytes: 400 * 1048576,
             kernelUpgradePending: false, rebootRequired: false };
  },
  /** 采集环境画像（probe.facts 的数据源）。 */
  async probeFacts(target) { return factsObject; },
  /** 按计划执行。plan.resolvedArgv 是 argv 数组的数组（pre + cmd）。 */
  async apply(plan, { runId }) { return { exit: 0, stdout: '', stderr: '' }; },
  /** 可选：连接状态。缺省时 engine.connectionState 返回 'unknown'。 */
  state() { return 'connected'; },
};

createEngine({ dir, transport, controllerHandlers: new Map([...]) });
```

**契约细节（踩了就会静默失效）**：

1. **`check` 必须返回 `probed: true`。** 否则 `checkFingerprint()` 返回 `null`，计划在任何情况下都判"不新鲜"→ 永远无法执行。
2. **`check` 的结果里不要放时间戳/耗时。** 指纹用**排除法**（新增字段默认纳入），
   所以加一个 `probedAt` 会让每次判定都"环境已变"。易变信息放 `note`。
3. **`apply` 抛出的错误不要包含凭据。** 引擎会在工具出口脱敏，但别依赖它兜底。
4. **续跑语义**：`apply` 中途断连**不等于失败**。远端可能已生效 →
   重连后应先用该动作的 `check`/`verify` 判断 `applied` / `not-applied` / `unknown`，**不要盲目重放**。

**建议实现顺序**（每步都能独立验证）：

| 步 | 内容 | 验收 |
|---|---|---|
| 1 | `dsh plugin --profile web add ssh2` 装依赖（加到 `packages/plugin-host/package.json` 的 dependencies） | 能 `import('ssh2')` |
| 2 | 实现 `probeFacts`：连接 → 执行 `vmprobe --check` → 解析 JSON → 存 `engine.factsByTarget` | 用假目标不行；需要一个真实可达的 Linux（容器即可） |
| 3 | 实现 `check`：先只支持 `probe.facts`（`check:{probe:'none'}` → 返回 `{probed:true, reachable:true}`） | `vmprobe_action probe.facts` 能走完 R0 全流程并落审计 |
| 4 | 若目标是容器/本机，先做 **`ssh2` 连本机 sshd** 或 `docker exec` 传输层做端到端 | 21 个探测点照旧全绿 + 新增传输层探测点 |
| 5 | 连接复用 + keepalive：单 `Client` + 多 exec channel；`keepaliveInterval: 15000`、`socket.setKeepAlive(true, 30000)` | 空闲 30 分钟后首条命令 < 200ms |
| 6 | SFTP 推送 agent 二进制 + `--sha256` 安装 | `agent.install` 走通，`vmprobe --selfcheck` 有输出 |
| 7 | **免密登录事务**（见下） | 破坏性测试：故意让验证步骤失败，**旧连接必须仍可用** |

**免密登录事务的不可违反之处**（设计决策 D3，`DESIGN.md` §8.2）：

```
生成专用密钥 → 幂等写入 authorized_keys（先备份） → **另开一条连接用密钥验证成功**
  → 成功：才切断旧密码连接、抹除内存中的密码、切换 authRef
  → 失败：回滚 authorized_keys、**保留旧连接**、报告原因
```

核心不变式：**任何时刻至少存在一条可用的连接路径。**
按字面"配完就切"的实现在遇到 `PubkeyAuthentication no` / StrictModes 权限问题时，
会**永久锁死那台服务器**，只能走 VNC/控制台救回来。

实现为 `controllerHandlers` 里的一个处理器（`apply.default.handler = 'auth.enablePasswordless'`），
**必须**用 `engine.redactor.add(password)` 登记密码、用完 `clear()`，保证它不出现在任何日志/错误里。

**还要做的两件事**：
- 把 `transport` 传进插件：目前 `packages/plugin-host/src/index.js` 里写的是 `transport: config.transport ?? null`，
  为 `null` 时 `connectionState` 返回 `'not-wired'`、`canApply` 为 false（fail-closed）。
- 传输层接线后，`vmprobe_facts` 工具才有意义 → 那时再注册它（**别提前注册一个永远报错的工具**）。

---

### R4 —— 新增客户端 UI（M1 后期）

1. 新建 `packages/plugin-client/`，其 `package.json` 也要声明 `dsh.bundle.patch` 与自己的 `cordis.patch.yml`。
2. 贡献 slot（已核实的 id 见 §5.3）：`conversation.session.header.actions` 放连接状态徽标。
3. 数据**由 host 算好**、经推送帧到达，客户端只渲染（照 `dsh-client-ui-jobs` 的思路：不发 RPC、不持状态）。
4. 自带 `vmprobe.*` locale 命名空间，中英双语。
5. ⚠️ **未经核实**：客户端插件热更新是否必须同时运行 `pnpm run dev:web`。第一次做时先验证这一点。

---

### R5 —— 调整风险分级 / 审批策略

**改这里**：`packages/core/src/risk.js` 的 `DEFAULT_POLICY`

```js
export const DEFAULT_POLICY = Object.freeze({
  autoAllowUpTo: Risk.R1,        // ← 改成 R0 就是"R1 也弹窗"
  prodEscalatesTo: Risk.R2,      // 带 prod 标签的目标把低于此级的行为提升上来
  alwaysAskFrom: Risk.R2,
  echoHostnameAt: Risk.R3,
  auditReadOnly: true,
});
```

改完**必须同步改** `packages/core/test/risk.test.js`（有一项断言直接锁定 `autoAllowUpTo === 'R1'`）。

> **⚠️ 不要试图通过插件配置改它**：`engine.config.autoAllowUpTo` 是**死键**（见 §9 债 #1）。
> 想让它真正生效，需要把 policy 从 engine 传进 `buildPlan({ policy })` —— 一个 5 行的改动，
> 但**先补测试**再改，否则会绕开现有的 fail-closed 断言。

其他相关点：

- 新增"提权依据"（例如"目标磁盘快满时升级风险级"）→ 改 `decideApproval` 的 `escalate` 分支 + 补测试。
- 改审批文案 → `buildApprovalReason()`。它受一个硬约束：**一句话说清"谁、什么、影响面"**，
  因为这是 `ApprovalRequest` 里唯一的自由文本通道。

---

## 7. 测试与调试

### 7.1 八层检查

```powershell
npm run check          # 全套
```

| 层 | 命令 | 性质 |
|---|---|---|
| 单元测试 | `npm run test` | 纯逻辑，**174 项**（core 140 + transport 9 + plugin-host 25），毫秒级 |
| 插件契约 | `npm run check:plugin` | mock ctx 上跑 `apply()`；**并用 DSH 自己的 schema 校验器验 `output.schema`/`parameters` 子集**（不用启动就能拦住"整棵树加载失败"这类错）；**并用 DSH 自带的真实 cordis 起一棵最小插件树**（兄弟 entry 提供服务、VMProbe 未注入）—— 专门守住"可选服务怎么读"这类只有真机才会炸的错 |
| 故障推演 | `npm run check:faults` | 21 个探测点，用假传输层走真实执行路径 |
| **SSH 端到端** | `npm run check:ssh` | **真实 ssh2 服务端** + Git bash 作为远端 shell：握手/认证/主机密钥/exec/stdin/文件/超时 + 免密事务（含失败回滚）+ 心跳三态（成功/干净断开/静默死亡）+ **M2 的 verify 四情形与取消贯通**（27 项） |
| **归档** | `npm run check:archive` | 导出 → **外部实现交叉验证**（PowerShell `Expand-Archive`）→ 导入干净目录逐文件比对 → 私钥加密与错误口令（12 项） |
| 文档一致性 | `npm run check:docs` | 确认文档提到的项目内路径真实存在 |
| 环境预检 | `npm run check:doctor`（或 `npm run doctor`） | 离线检查 DSH 环境（凭据 / bundles / id 冲突 / 活实例） |
| 协从端脚本 | `npm run check:agent` | 语法 + 转义 + 安装守卫（自动定位 bash，无需改 PATH） |

**写新检查时的四条经验**（都是踩出来的）：

1. **能借宿主的校验器就别自己写规则。** 例如 JSON Schema 子集：与其自己列"哪些关键字允许"，
   不如直接 `require('@deepseek-ai/dsh-tools').assertSupportedJsonSchema(schema)` ——
   规则永远与宿主一致，不会漂移。
2. **失败注入比"跑一遍成功路径"值钱得多。** 免密事务之所以敢说"不会锁死机器"，
   靠的是把 `verifyKeyLogin` 换成必然抛错的桩，然后断言 authorized_keys 已回滚、旧连接仍能执行命令。
3. **桩只能用来制造失败，不能用来验证成功。** 成功路径一律走真实协议，否则你验证的是
   自己的桩（心跳恢复路径就差点掉进这个坑）。
4. **注意"谁在第几次探测时观察"。** 有状态的组件（比如失败后自动把会话标 `detached` 的心跳）
   会让第二次探测看到与前一次不同的世界；断言必须明确"这一次探测由哪一层、在什么状态下发出"。
5. **"没发生"类断言必须跨过"本该发生的时刻"。** 断言"标记文件不存在"时要问：
   它在别的情况下**什么时候**才会存在？如果命令本来要 20 秒才写文件，而我只等 4 秒就断言"没写"，
   这个断言**恒真**，与"取消有没有生效"毫无关系 —— 而且它会**盖住真错误**
   （实测：取消曾报成成功，测试却是绿的，见 `ISSUES.md` §12.6）。
6. **一个动作同时触发两条完成路径时，语义要由"单一裁定点"决定。**
   关闭 SSH 通道会让 `close` 事件到达，而它既可能是"命令正常跑完"，也可能是"我们把它关了"——
   两者的 `close` 长得一模一样。我第一版让 abort 路径自己去 reject，结果 `close` 先到把结果 resolve 成**成功**。
   正确做法：用标记（`aborted`）在 `close` 里统一裁定。

### 7.2 怎么加一个"探测点"（最有价值的测试形式）

`tools/checks/simulate-faults.mjs` 的设计很特别：**判据写的是"修复后应有的正确行为"**，
所以同一个脚本既是验伤工具（修复前报"缺陷已复现"）又是回归测试（修复后报"未复现"）。

```js
record('Fxx', '严重', '一句话描述这个问题', isDefect, [
  `关键观测值 = ${...}`,      // 尽量打印"实际观测到的值"，而不是只说"失败了"
  '为什么这是问题 / 修法要点',
]);
```

`isDefect` 为 `true` 表示"缺陷存在"。脚本最后按此统计并以退出码反映。

**这个形式的两个纪律**：

1. **判据要写"正确行为"而不是"复现步骤"**，否则修好之后脚本会一直红。
2. **失败时先怀疑自己的期望值，再怀疑代码。** 本项目里出现过两次：一次是我用正则匹配整个绝对路径
   把**盘符冒号**当成非法字符；一次是我把 86 天前的日期当成了"超出 90 天窗口"。
   把断言改松让测试变绿，和查清哪个才是对的，是两件完全不同的事。

### 7.3 真机验证的纪律

**核心纪律：不要碰正在服务的实例。**

```powershell
# 用临时端口另起一个实例（--port 0 让系统自选空闲端口），看完即关
dsh --profile web --no-open --port 0
Get-Content "$env:USERPROFILE\.dsh\vmprobe\loads.jsonl" -Tail 3
```

为什么这么严格：**本 agent 进程是 `dsh web` 的子进程**。
如果你在 DSH 里跑 agent 又去 kill `dsh web`，等于杀掉自己 —— 而且一旦环境本身有问题
（例如凭据文件坏了），**DSH 就再也起不来了**。这条真的发生过（`ISSUES.md` §9.1）。

### 7.4 排查三件套

| 想知道 | 看哪里 |
|---|---|
| 插件加载了没 / 定时器起来没 | `<storageDir>/loads.jsonl`（事件流） |
| 某个动作做了什么决策 | `<storageDir>/logs/audit.jsonl` 里的 `action.plan` / `action.approval` / `action.stale` |
| 环境本身有没有坑 | `node tools/doctor.mjs` |

---

## 8. 二次开发硬约束

这五条是项目一路推演出来的底线。**违反它们会引入"静默错误"，而不是明显的崩溃。**

### 8.1 fail-closed 优先

拿不准时**拒绝执行**，不要"尽力而为"。现有所有 fail-closed 点：

| 情形 | 行为 |
|---|---|
| 审批服务不可用 / `exec.agent` 缺失 | 拒绝执行（不"无审批器就放行"） |
| 审批返回非 `allowed-once` | 拒绝 |
| 计划过期 / 状态指纹不符 / 无法验证指纹 | 判 `stale`，要求重新计划 |
| 动作参数未接线（偏离默认值） | 阻断，并点名是哪些参数 |
| 无法为发行版解析出命令 | 阻断（**不要返回空 argv 假装成功**） |
| 参数类型/键名非法 | 阻断 |
| R3 但"复述主机名"机制未实现 | 阻断（**不要记一笔"跳过了"然后继续**） |
| 动作目录里有未知字段 | 拒载整个动作（**不要静默忽略** —— 拼错 `risk` 会降级安全属性） |
| 协从端安装未提供 sha256 | 拒绝安装（除非显式 `--no-verify`） |
| `id` 含路径分隔符 | 拒绝（它会进入文件路径） |

### 8.2 绝不谎报

这条比 fail-closed 更微妙，也更值钱。**"看起来成功、实际没做"比直接报错危险得多**，
因为它摧毁的是人对审计的信任。项目里三次踩到同一形态：

| 缺陷 | 谎报成什么样 |
|---|---|
| F2 | 参数被静默忽略 → 用户以为"只装安全更新"，实际执行全量升级 |
| F14 | 无匹配发行版 → 返回空 argv，**"计划成功、实执空转"** |
| A1 | 待更新数查询失败 → 退回 `0` → 被读成"没有待更新"（更安全的假象） |

**具体规则**：

- **不知道就记 `null`，不要填 `0`/空串/`false`。** `extractMetrics`、`bootstrap.sh` 的 facts 都遵守这条。
- **能力未就绪就不注册工具。** 注册一个永远报错的工具会白占 token 并诱使模型调用它。
  现在 `vmprobe_facts`/`report`/`archive` 就是**故意不注册**。
- **缺数据就报缺。** 日报缺天不补造，用 `findGaps()` 如实列出。
- **连接状态等"看起来像真值"的字段不许硬编码。** 未接线时返回 `'not-wired'`，
  而不是一个像样的 `'detached'`（缺陷 I9）。
- **不可达也要落文件**（`status: 'unreachable'`），否则"没有文件"无法区分"没跑"与"连不上"。

### 8.3 确定性

审计的哈希链要求可重现：

- 一切进哈希的内容先过 `canonicalJson`（递归键排序）。
- **不要把时间戳/耗时放进 `check` 结果**（会污染状态指纹，导致"永远过期"）。易变信息放 `note`。
- `presentCall` / `presentResult` / `output.render` 必须是**纯函数** ——
  它们在会话重放时也会被调用，所以只能依赖 `(args)` / `(args, result)`，不得读运行时状态。
- 审计里不要放非有限数值（`NaN`/`Infinity` 会被 `canonicalJson` 拒绝，这是有意的）。

### 8.4 契约纪律

- 函数插件**不得有 `default` 导出**（会丢掉 `inject`）。
- `ToolDefinition.output` **必填**；声明 `timeoutMs` 就必须真的支持协作式取消。
- **文档里承诺的 CLI 必须真的存在**：缺陷 F10 就是目录里写着 `vmprobe probe facts --json`，
  而协从端脚本里根本没有这个子命令 —— 接上传输层后会直接 command not found。
  改任一边（目录 / 脚本）都要同步另一边。
- 审批请求只有 `reason` 一个文本通道，**别再试图往里塞富文本**。

### 8.5 凭据纪律

- **判定"哪个键名算秘密"只有一处实现**：`core/src/store.js` 的 `isSecretKeyName()`。
  `assertSecretFree`（写入拒绝）与 `redact.js`（输出脱敏）共用它 —— 两处各写一套迟早漂移成"一边拦一边放"。
- **脱敏只有两个关口**：`engine.record()`（审计写入前）、`createTools()` 的统一出口（错误文本）。
  新增任何"把内容送出去"的路径，都要过其中之一。
- **你自己的调试脚本也不许打印凭据值。** 本项目所有相关工具都只输出"键名 / 长度 / sha256"，
  例如 `tools/fix-credentials.mjs` 用逐值 sha256 证明"值没被改动"，而不是把值打出来给你看。
- 凭据不随归档迁移；`authRef` 是引用，不是值。

---

## 9. 已知限制与技术债

按"会咬人的程度"排序。

| # | 项 | 影响 | 建议 |
|---|---|---|---|
| 1 | ~~`autoAllowUpTo` 与 `allowRawShell` 是死键~~ ✅ **已修（M2）** | — | core 的判定现在真的读 `autoAllowUpTo`；插件把策略透传进 `buildPlan`；`allowRawShell` 被**明确拒绝并告警**（T3 未实现），不再假装是个开关 |
| 2 | ~~`verify` 阶段没有真正执行~~ ✅ **已修（M2）** | — | 见 D7.5：`verify { probe, expect, maxWaitMs }` 三态结论 + 真实 SSH 覆盖 |
| 3 | ~~工具仍不声明 `timeoutMs`~~ ✅ **已修（M2）** | — | 见 D7.7：`exec.signal` 贯通后声明（额度取目录最长动作预算 + 余量） |
| 4 | **审计链无密钥（可篡改痕迹，不可防伪造）** | 拥有审计目录写权限且愿意重算整链的攻击者可以伪造 | HMAC：密钥放凭据库、不进归档（建议列入 M5） |
| 5 | ~~`pruneReports()` 未接定时器~~ ✅ **已修（M2）** | — | 调度器每天清理一次（幂等键 = UTC 日键） |
| 6 | ~~运行输出体没有独立文件~~ ✅ **已修（M2）** | — | 见 D7.6：`runs/<runId>.log` + sha256 入审计 |
| 7 | **只有 SSH 一个传输后端** | 想在同一台机器/容器里验证或使用，得先起 sshd | 加一个 `local`（直接 spawn）与 `docker exec` 后端；测试也更好写 |
| 8 | **plan TTL（默认 5 分钟）与人工审批耗时的张力** | 用户思考超过 5 分钟，计划就过期，模型需重新计划并**重新申请审批** | 这是刻意的（环境可能已变）。但要在工具描述与渲染里把"请重新计划"讲清楚 |
| 9 | ~~`I5` 待决策：`approval` 是否保持必需注入~~ ✅ **已决策并落地** | — | 改为 `inject=['tools']`：**加载不阻塞、执行时 fail-closed**（DESIGN D14）。原方案"缺审批就不加载"的理由没错、手段错了 —— 一个可选服务的缺失不该有让整棵树加载失败的权力（ISSUES §13.1） |
| 10 | ~~宿主 `yaml` / `dsh-tools` 由绝对路径加载~~ ✅ **已修（M2）** | — | 见 `tools/lib/dsh-runtime.mjs`：按环境变量 → `dsh` 位置 → Node 前缀逐层探测，含 DSH 自身嵌套依赖；四个工具里的写死路径全部消除 |
| 11 | **客户端 UI 插件（浏览器侧）受环境阻塞** | 没有状态徽标/设置页；凭据录入只能走命令行 | **实测证据**：发行版里没有 tsdown/esbuild/rollup/vite/tsup 任一打包器；`@deepseek-ai/dsh-client-*` 未发布到 npm；客户端 bundle 是内部格式（`window.__ModuleLoader__.load({id, factory})`）。在没有打包工具链、又不能重启用户活动实例的前提下**手写这个 bundle 属于不可验证的改动**，因此不做。替代：把同样信息做进对话（结果卡片带校验结论、`vmprobe_status` 带配置警告）+ CLI 掩码录入 |
| 12 | 未处理的告警源：`ctx.systemPrompt.section` 签名未核实 | 基础用法提示可能没注入（完整用法仍可从 `vmprobe_catalog` 拿到） | 已做守卫 + 明确告警 |
| 13 | ~~运行日志 `logs/run.jsonl` 未单独落文件~~ ✅ **已完成** | — | 与审计分工的独立运行日志（DESIGN D16）；已加"不得每次写入都轮转"的回归测试（ISSUES §13.3） |

---

## 10. 路线图 M1–M5

### M1 —— 真正能连上并执行 ✅ **已完成**

| # | 任务 | 结果 |
|---|---|---|
| ① | **SSH 传输层**（ssh2：密码/密钥认证、连接复用、keepalive、超时、文件投递） | ✅ `packages/transport/src/ssh.js`；25 项端到端验证通过 |
| ② | **参数 → argv 接线机制** | ✅ 由 argv 用法自动推导接线情况；`system.update` 的 `securityOnly`/`exclude`/`dryRun` 真正生效，不支持的分支 fail-closed |
| ③ | **`probe.facts` 接真机 + 落盘** | ✅ 引导脚本经 stdin 投递（零安装）；facts 落盘 + 内存/磁盘回退 |
| ④ | **掩码凭据录入** | ✅ `tools/vmprobe-cred.mjs`（命令行方案，客户端 UI 推到 M2） |
| ⑤ | **免密登录事务** | ✅ 启用 + 撤销两个对称事务；含**失败注入测试**证明不会锁死机器 |
| ⑥ | 注册 `vmprobe_facts` 工具 | ✅ 第 6 个工具，契约测试含 schema 子集校验 |
| ⑦ | 心跳保活 | ✅ 长连接 + keepalive（15s×4）**加**主动心跳观测：60s 一次、只探活跃会话、失败即标 `detached`、状态变化才写审计；`vmprobe_status` 显示延迟/失败次数/最初失败原因 |
| ⑧ | **认证切换记住原凭据**（`previousAuthRef`） | ✅ 撤销免密不再因为 ref 被覆盖而拒绝；启用→撤销→口令重连形成闭环 |

### M2 —— 执行的可信度与体验 ✅ **① ② ③ ⑤ ⑦ 已完成；④ 受环境阻塞；⑥ 无 Linux 目标**（2026-09-14）

| # | 任务 | 结果 |
|---|---|---|
| ① | **`verify` 真正执行** | ✅ 见 D7.5；`system.update` 声明 `expect { count: 0 }`，执行后重探测并给出"还剩几个包"；三态结论（真/假/未判定）分开报 |
| ② | **运行输出落盘**（`runs/<runId>.log`） | ✅ 见 D7.6；带 sha256、写入前脱敏、超限截断标注、失败与取消同样落盘 |
| ③ | **取消/超时贯通** | ✅ 见 D7.7；真实 SSH 验证"远端命令不再继续、连接仍可用"；`timeoutMs` 已声明 |
| ④ | 客户端 UI 插件 | ⛔ **受环境阻塞**（技术债 #11 有实测证据）；宿主侧替代已做：结果卡片带校验结论、状态工具带配置警告 |
| ⑤ | 主动心跳与连接健康观测 | ✅ 见 M1 ⑦ |
| ⑥ | 真实 Linux 目标验证 | ⛔ **本机没有 Linux 目标**（WSL 无发行版、无 docker/podman）；真实 SSH 协议已覆盖，发行版行为仍是模拟（见 `ISSUES.md` §10.4） |
| ⑦ | 修技术债 #1 / #5 / #10 | ✅ 三项全部完成，另有第 13 项（`run.jsonl`）新登记 |

**M2 的验收测试**：新增 `packages/transport/test/probe-satisfies.test.js`（9 项）、
`packages/plugin-host/test/runs.test.js`（7 项）、`packages/plugin-host/test/m2-engine.test.js`（14 项），
并在真实 SSH 上加了两节（verify 四情形 + 取消贯通）。单测总数 **113 → 143**，SSH 端到端 **25 → 27 项**。

### M3 —— 归档与迁移 ✅ **已完成（2026-09-15）**

| # | 任务 | 结果 |
|---|---|---|
| ① | `.vmpz` 导出/导入 | ✅ **标准 zip**（自研容器 `packages/core/src/zip.js`，~200 行、零依赖，走 Node 自带 zlib）+ 清单 + 逐文件 sha256 + schema 版本校验 |
| ② | 默认不含凭据；`--include-secrets` 必须加密 | ✅ 私钥默认不入档；要带就**必须**加密（scrypt + AES-256-GCM），"带秘密但不加密"直接拒绝；口令只从 TTY 或环境变量给 |
| ③ | 导入前差异预览 | ✅ 新增 / 一致 / 冲突 / **凭据缺口** 四类；默认 `--dry-run`，`--apply` 才落盘，默认不覆盖（覆盖要 `--overwrite` 且**先备份**） |
| ④ | 脱敏档位 | ✅ `none` / `minimal` / `standard`（IP 与主机名打码、标签清空；`authRef` 引用名保留） |
| ⑤ | （超出原计划）**审计密钥永不入档** | ✅ 硬编码排除 + 测试盯着；否则"抗伪造"的根随归档流出去，HMAC 等于白做 |
| ⑥ | （超出原计划）**外部实现交叉验证** | ✅ `tools/checks/check-archive.mjs` 把导出的归档交给 **PowerShell `Expand-Archive`** 解 —— 证明容器符合规范，不是"只有我自己能读"的私有格式 |

**验收**：`packages/core/test/archive.test.js`（15 项）+ `tools/checks/check-archive.mjs`（12 项断言，含外部解压）。

### M4 —— 协从端守护进程与本地定时 ⛔ **刻意推迟（无 Linux 目标，无法验证）**

- 计划内容：`--daemon`（unix socket，不监听 TCP）+ 任务流式输出 + 断连续跑；本地定时报告；
  systemd unit / logrotate / 窄规则 sudoers；多目标 fan-out。
- **为什么现在不做**：这个里程碑的价值**全部**落在 Linux 特有行为上 ——
  unix socket 权限、systemd 生命周期、logrotate、sshd 的 StrictModes/SELinux 上下文。
  本机没有 Linux 环境（WSL 无发行版、无 docker/podman），**写了也只能验证到一半**，
  而"半验证的守护进程"比"明确没做"更危险：它会被当成已经可靠的东西而进入生产。
- **具备条件后**：拿到一台真实 Linux 目标即可开工，验收标准见本节表格（届时补回）。

### M5 —— 硬化 🟡 **部分完成**

| 项 | 状态 |
|---|---|
| **审计链 HMAC**（抗伪造，含降级规则与密钥轮换边界） | ✅ 已完成（DESIGN D15，12 项单测） |
| 运行日志与审计分工（避免日志格式变更破坏证据链） | ✅ 已完成（DESIGN D16） |
| 威胁模型逐条对策 + 测试（§9.1 的 T1–T10） | ⏳ 待办 |
| 指纹固定与变更处置流程、主机密钥轮换动作 | ⏳ 待办（指纹固定已实现，轮换动作未做） |
| 动作目录模糊测试；T2 白名单与 T3 原始 shell 的护栏 | ⏳ 待办（T3 现在被明确拒绝，见技术债 #1） |
| 文档与真实行为的一致性审计 | 🟡 持续做（`check:docs` 只查路径存在，查不了语义漂移） |

---

## 11. 单台 → 多台的演进路径

当前为单台做的简化与**对应的改动点**（按依赖顺序，不要跳步）：

| 步 | 改动 | 说明 |
|---|---|---|
| 1 | **连接池**：`transport` 从"单实例"改成"按 targetId 取实例 + 生命周期管理" | 现在 `createEngine({ transport })` 只接受一个传输层对象 |
| 2 | **每目标串行队列** | 现在靠"工具不声明并发安全"隐式串行；多目标要显式队列，避免包管理器锁冲突 |
| 3 | **facts / 报告的批量视图** | 报告已按 `<targetId>` 分片，但有汇总需求时需要一个聚合读取层 |
| 4 | **凭据批量管理** | 单台可以手填；多台需要导入/轮换/失效检测流程 |
| 5 | **报告汇总与分组** | 按 `tags`（`prod` 等）分组，避免"一天几十个文件没人看" |
| 6 | **存储索引** | JSON + JSONL 在几十个目标 × 一年报告下会变慢，考虑 sqlite（DSH 已有 `dsh-session-query-sqlite` 可借鉴） |
| 7 | UI | `conversation.session.header.actions` 里的"目标切换 Popover"从可选变成必需 |

**不建议跳步的原因**：第 1 步没做之前，第 3–6 步都是在为"事实上只有一台"的架构做优化；
而现在 `transport: null` 的 fail-closed 行为意味着**加多目标不会带来安全风险**，只是没收益。

---

## 附：改动前检查清单

动代码前过一遍，能避免本项目历史上踩过的绝大多数坑：

- [ ] 这次改动会不会**让某个"做不到"变成"看起来做到了"**？（§8.2）
- [ ] 新的失败路径是 **fail-closed** 还是"尽力而为"？（§8.1）
- [ ] 新增的内容会不会进审计哈希？要不要过 `canonicalJson`？有没有引入非确定性？（§8.3）
- [ ] 有没有把凭据送到新的出口？要不要过脱敏？（§8.5）
- [ ] 改了目录/脚本一边的 CLI，另一边同步了吗？（§8.4）
- [ ] 加了动作 → 更新了那两处"恰好 N 个动作"的断言吗？
- [ ] 加了工具 → 声明 `output` 了吗？需要 `presentCall` 吗？
- [ ] 改完跑了 `npm run check` 和 `npm run doctor` 吗？
- [ ] 要验证加载 → 用 `--port 0` 临时实例，**不要碰正在服务的实例**（§7.3）
