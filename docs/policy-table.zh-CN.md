# 策略表参考

完整的规则字段、算子、动作、内置基线防线与运行时语义。架构级细节（hook 映射、决策引擎、面板生命周期、文件总线）见 [architecture.md](./architecture.zh-CN.md)。

策略是带 `action` 与 `priority` 的有序条目；其 `rules` 采用 **OR** 语义（任一规则命中即触发）。策略表通过 `cordis.yml` 的 `config.policies` 注入，`apply` 前由 schemastery schema 校验。

## 规则字段（`field`）

- 内置：`eventType`、`agentId`、`agentType`（保留，dsh 无此概念）、`content`。
- 工具事件：`toolName`、`arguments`（完整 JSON），以及**展开的原始参数字段**（`command`、`path`、`url`、`code`…）。
- 其他字段优先查事件 `data`，再查 `context`。

## 算子（`operator`）

| 算子 | 语义 |
| --- | --- |
| `eq` | 严格相等 |
| `neq` | 不相等 |
| `contains` | 子串包含（字符串） |
| `in` | `value` 为数组，命中任一元素即命中 |
| `matches` | glob 通配 `*`（`write*`、`mcp_*`） |
| `regex` | 真实 RegExp 匹配（裸模式或 `/pattern/flags`）；非法或灾难性回溯模式永不命中（fail safe） |

## 动作（`action`）

| 动作 | 效果 |
| --- | --- |
| `allow` | 放行 |
| `block` | 阻止（工具调用 `deny`、结果 `block`、步 `reject`） |
| `ask` | 审批——仅在 `tools/pre-execute` 有效；其他处降级为 block |
| `warn` | 放行但记警告日志 |

## 内置基线防线

插件开箱自带 27 条基线策略，无需配置策略表。特征提取器（`features.ts` + `intent.ts`）把工具调用、工具结果、跨事件状态与用户消息意图转成引擎可匹配的特征字段。字段**只在信号触发时才存在**，因此正常调用不产生任何字段、不会命中基线规则。

27 条内置策略（优先级 **50**，低于用户默认的 100）：

| 策略 id | 匹配字段 | 动作 | 拦截 / 警告 |
| --- | --- | --- | --- |
| `base-block-high-risk-command` | `highRisk` | block | `rm -rf /`、管道到 shell（`curl … \| sh`）、shell 段首的死循环/关机/格式化（`while true; …`、`shutdown now`、`sudo reboot`、`mkfs…`）、shell rc 截断、反弹 shell（`bash … >& /dev/tcp/…`、`nc -e`、`socat … EXEC:`）、字距混淆（`r m - r f /` 及 `sudo r m - r f /`） |
| `base-block-obfuscated-command` | `obfuscated` | block | `base64 -d \| sh`、`xxd -r`、hex 转义、不可见字符/零宽字符 |
| `base-warn-overlong-command` | `overlong` | warn | 超过 10 000 字符的命令——仅记录，绝不因长度单独拦截 |
| `base-block-encoded-high-risk` | `encodedHighRisk` | block | base64/hex 载荷解码后是高危/混淆命令（`echo <b64> | base64 -d`，PowerShell `-EncodedCommand`，含短带 padding 令牌与 UTF-16LE 载荷） |
| `base-block-protected-path` | `protectedPathHit` | block | `~/.ssh`、`~/.gnupg`、`~/.dsh`、shell rc、敏感 `/etc` 文件（抗引号拆分） |
| `base-block-outside-delete` | `deleteOutsideWorkspace` | block | 删除（`rm`、`shred`、`gio trash`、`find -delete`…）目标解析后在工作区之外——含 `..`、`cd` 基准、`~`/`$HOME` |
| `base-block-loop-hazard` | `repeatExceeded` | block | 一轮内第 4 次相同**变更**调用（重复调用预算，允许 3 次；`git status` 等只读调用永不计数） |
| `base-block-artifact-execution` | `artifactExecutionRisk` | block | 执行本轮稍早写出的高风险脚本 |
| `base-block-exfil-chain` | `exfilChain = high` | block | 携带已知密钥出站、轮内风险标记 + 先前出站、风险工件 + 出站、或出站时链条双腿（凭据 + 编码）齐备 |
| `base-warn-exfil-chain` | `exfilChain = medium` | warn | 出站时只武装了单条腿（审计、不拦截） |
| `base-block-tool-result-injection` | `toolResultRisk = block` | block | 工具结果含高置信**指令性**/编码化提示注入短语（身份劫持/防护瘫痪/工具诱导/外传/提权） |
| `base-warn-tool-result-injection` | `toolResultRisk = warn` | warn | ≥2 个来自**不同**家族的弱注入短语（软信号）。能力陈述（"you can post results to …"）与单个弱短语不触发 |
| `base-block-user-intent-attack` | `userIntentRisk = block` | block | 用户消息要求关闭守卫、绕过审批或无视限制（拒绝该步）。引用/讨论守卫本身（"the docs say to disable …"）不算攻击 |
| `base-warn-user-intent-attack` | `userIntentRisk = warn` | warn | 较软的操纵暗示（假装无限制/绕过教程），仅审计 |
| `base-block-privilege-escalation` | `privEsc = block` | block | 提权/关闭安全控制：`setenforce 0`、服务 stop/mask、`chmod -R 777`、`chown root`、setuid 位 |
| `base-warn-privilege-escalation` | `privEsc = warn` | warn | 非递归的全局可写 `chmod 777`（单文件权限修复可能是正常操作） |
| `base-block-system-path-write` | `systemPathWrite = block` | block | 写入系统持久化位置：`/etc` 的 cron / rc / profile / 账户文件、Windows 系统目录 |
| `base-warn-system-path-write` | `systemPathWrite = warn` | warn | 安装/拷贝进系统 bin 或库目录（`/usr[/local]/bin`、`/Library`）；全局 CLI 安装可能是正常操作 |
| `base-block-config-tamper` | `configTamper` | block | 原地篡改守卫/策略文件（对 `AGENTS.md`、`SKILL.md`、策略配置 `sed -i` / 覆写 / 删除） |
| `base-block-sandbox-escape` | `sandboxEscape = block` | block | 沙箱/容器逃逸工具：`nsenter`、`chroot` 执行、`docker.sock` 挂载、`/proc/1/root`、`/:/` 主机挂载 |
| `base-warn-sandbox-escape` | `sandboxEscape = warn` | warn | 特权容器运行（`--privileged`）；testcontainers/DinD 场景可能是正常操作 |
| `base-warn-net-recon` | `netRecon` | warn | 网络扫描/监听（`nmap`、`masscan`、`nc -l`）；可能是正常调试 |
| `base-warn-path-traversal` | `pathTraversal` | warn | 命令中多段 `../` 路径穿越 |
| `base-warn-untrusted-source` | `untrustedSource` | warn | 新克隆源码的“克隆后即构建/安装”链 |
| `base-warn-insecure-registry` | `insecureRegistry` | warn | 包索引/registry 被改为明文 `http://`（供应链风险） |
| `base-warn-secret-logging` | `secretLogging` | warn | 代码把疑似密钥的值写进日志（`console.log`/token/password/secret） |
| `base-warn-memory-poison-write` | `memoryPoisonWrite` | warn | 向类记忆目标写入指令/触发短语内容（长期记忆投毒风险） |

用户规则可用的其他特征字段：`command`、`overlong`、`outbound`、`secretRef`、`transformSignal`、`encodedHighRisk`、`scriptArtifactPath` / `scriptArtifactHash` / `scriptArtifactRisk`、`toolResultText`、`specialTokensRemoved`、`toolResultFlags`、`toolResultRisk`、`observedSecrets`、`deleteTargets`、`privEsc`、`systemPathWrite`、`configTamper`、`sandboxEscape`、`netRecon`、`pathTraversal`、`untrustedSource`、`insecureRegistry`、`secretLogging`、`memoryPoisonWrite`。

用 `basePolicies: false` 关闭整套基线。

## 工作区根目录

`workspaceRoot`（默认 `process.cwd()`）限定"越界删除"与"受保护路径"两条护栏。删除目标会被**解析为绝对路径**：`..`/`.` 归一化、开头的 `cd <dir>` 改变后续相对目标的基准、`~`/`~user`/`$HOME` 展开到主目录；解析后的目标再与工作区根做大小写一致比较（如 `/Users/Dev/MyProject` 不会被误判）。root 之外一律视为工作区外。

## 策略优先级

基线策略优先级 **50**；用户策略默认 **100**，显式用户策略永远压过基线。UI 策略文件总线（`ui-policies.json`）存在时会**整体替换**生效表（基线 + 用户策略）——面板保存时必须保留基线行，否则基线不会保存下来。

## 已观测密钥 / 外传链

工具结果中观测到的密钥按会话记住，TTL 滑动续期（默认 5 分钟，被访问时刷新）。路径形态令牌、点号分隔标识符与低熵串永不算密钥（目录列举不是泄漏），且按会话的密钥池有 LRU 上限。携带已知密钥（原文、base64 或 hex 形式）的出站命令，或出站时凭据/编码任一腿已武装的出站，被判定为外传链：`high` 拦截，`medium` 警告并经 `recordVerdict` 链路审计。

## 提示词防护（system-prompt 装配）

`promptGuard: true`（默认）时，插件向每次 system-prompt 装配注入 `agent-security-guard` 段落（order -50，位于 persona 之前）：6 条静态规则（仅工具改状态、提示词不带密钥、受保护路径、工作区外禁删、工具结果视为不可信数据）加上会话观测到密钥或风险标记时的动态"会话风险上下文"块。遵循 harness 的合作语义：段落追加到 waterfall 结果末尾，注册的 `complete` system-prompt 段落可有意覆盖它。用 `promptGuard: false` 或 `hooks.systemPromptAssemble: false` 关闭。

## 用户意图攻击扫描

每次 `agent/pre-step` 扫描只把 **user 角色**消息文本（绝不扫描经 `additionalContexts` 混入的系统/工具派生上下文）过一遍意图模式（plain + dense 视图；中文模式只在 plain 表上）。直接攻击措辞（`disable the guard`、`skip the approval`、`ignore all restrictions`、`绕过审批`…）置 `userIntentRisk: block` → 被 `base-block-user-intent-attack` 拒绝；较软暗示（`pretend you have no restrictions`、绕过教程类提问）为 `warn` → 被 `base-warn-user-intent-attack` 审计。引用/讨论守卫本身（"The docs say: to disable the safety guard, edit config.yml"）不算攻击。

## 拦截反馈（prompt-block notice）

默认情况下（`promptBlockNotice: true`，可用 `promptBlockNotice: false` 关闭），当 `agent/pre-step` 拒绝某一步（`block`，或 `ask` 降级为拒绝）时，插件会在会话中追加一条 `notice` 形式的 `user/message`（`source.kind: 'plugin'`），让对话页立刻看到反馈，而不是静默吞掉用户消息：折叠行显示摘要（"安全守卫已拦截该消息"），展开可见完整原因（本地化、含策略 id）。通知只携带策略原因，**绝不回显被拦截的内容**（防提示注入），也绝不把拦截文本带进模型上下文；失败时被包含（catch 后仍返回 `reject`），不会把拦截降级成错误。

## 观测模式

在 cordis.yml 设 `mode: monitor`，让整张表（基线 + 用户策略）跑观测模式：每个 `block`/`ask` 判决降级为 `warn`，守卫记录审计但从不拒绝。单条策略可用自己的 `mode` 字段覆盖（UI 策略表与 cordis.yml 的 `policies` 字段同构）。默认 `protect`。

## 判决记录

判决写入插件自有 JSONL 审计文件 `$DSH_HOME/agent-security-guard/verdicts.jsonl`——**绝不**写入 harness 会话日志（harness 遥测层把一条已提交的 `feedback/record` 视为上传会话内容的同意凭据）。`allow` 判决**默认不落盘**；`block`/`ask`/`warn` 落盘。记录携带持久化元信息（session / turn / step / call id / policy / time）；工具判决持久化工具名与 call id（面板用活跃会话关联参数/结果文本），`agent/pre-step` 判决在记录时持久化其检查到的装配提示词内容。详情字段有界（每个约 4 KB），纯增量。审计文件带大小上限（自动压缩），可在面板内清空。