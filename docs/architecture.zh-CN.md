# 架构说明

设计边界、源码结构、Hook 点、决策语义、审查链路与审查面板生命周期。

## 设计边界

- **本地有界同步决策**：`engine.ts` 不做任何外部调用。判决路径对单事件有界：`regex` 算子会拒绝已知灾难性回溯的模式（嵌套/交替量词组，含 `{n}` 重复形态）并限制输入长度，因此在已覆盖形态下同步决策不会冻结 harness 事件循环；非常规回溯形态超出当前审查面。
- **仅本地规则**：在线决策（远程策略服务）不在本插件范围内。需要时可在 `adapter.ts` 中扩展 `engine.decide` 调用点。
- **不包含沙箱 / 心跳 / 元数据上报**：本插件只做本地规则决策，不含这些能力。
- **不写 harness 会话日志**：判决只写入插件自有的审计文件（`verdicts.jsonl`），绝不使用 `feedback/record`（harness 遥测层把一条已提交的 `feedback/record` 当作上传会话内容的同意凭据）。
- **面板 API 默认仅限回环**：webServer 绑定 `127.0.0.1` 时注册 `/guard/api/*` 路由；非回环绑定只有存在显式 `webRuntime.trustedHosts` 白名单时才注册（见"面板 API 安全"）。

## 目录结构

包由两部分组成：host 侧（Node 代码，运行在 harness 进程内）与 client 侧（浏览器 bundle，通过 package.json 的 `dsh.client.inject` 由 DSH web 壳加载）。

```
src/
├── index.ts          # 插件入口：name / Config / apply；串联 engine、监听器、文件总线、模型阶段、面板 API
├── config.ts         # Config schema（schemastery）+ 语义校验 + UI 策略表 + 守卫偏好设置
├── types.ts          # GuardPolicy / GuardRule / GuardEvent / GuardDecision
├── engine.ts         # GuardEngine：规则匹配、优先级、failOpen；setPolicies 热替换
├── policy-store.ts   # 策略文件总线：watch + 热替换 + effective.json 镜像
├── guard-api.ts      # host 侧 /guard/api/* 路由
├── adapter.ts        # harness 事件 -> GuardEvent；判决 -> harness 决策；特征合并
├── features.ts       # 威胁特征提取（静态 / 有状态 / 工具结果）
├── command-threats.ts# 命令/内容类威胁族（融合自 operator_rules 基线）
├── threat-catalog.ts # 平台自适应规则目录（shared + posix / win32 / darwin）
├── platform.ts       # 平台解析：config.platform > DSH_GUARD_PLATFORM > 宿主 OS
├── intent.ts         # 用户意图攻击扫描（block / warn 风险特征）
├── patterns.ts       # 威胁模式库（工具结果注入短语、密钥引用、编码变换）
├── secrets.ts        # 已观测密钥检测
├── state-store.ts    # 会话/轮次状态（滑动 TTL；循环计数、信号、密钥，FIFO 上限）
├── base-policies.ts  # 内置基线策略（27 条，优先级 50）
├── normalize.ts      # 有界文本归一化（raw / normalized / compact）
├── decode.ts         # 有界 base64/hex/UTF-16LE 载荷解码（深度 2，可打印过滤）
├── prompt-guard.ts   # 系统提示词安全段落构造器
├── model-review.ts   # 模型审查阶段：caller、解析器、模板渲染、判决合并
├── audit.ts          # 判决 + 模型审查记录写入插件自有的本地 JSONL 审计文件
├── audit-prompts.ts  # 三条内置审查模板（恶意意图检测 / 风险指令检测 / 意图偏离检测）
├── hooks.ts          # hook 名归一化：原生 seam 与 seam 元数据
└── client/           # client 侧：面板 UI（index.tsx）、API 封装（api.ts）、多语言文案（locales.ts）、插槽类型（types.ts）
```

## Hook 点

策略表用 hook 名声明策略生效阶段。hook 名就是 deepseek-harness 的原生扩展点（`ctx.on` 事件名），插件不再引入自己的别名词汇：

| Hook（= deepseek-harness 原生 seam） | 模式 | 干预动作 |
| --- | --- | --- |
| `tools/pre-execute` | waterfall | `deny` / `ask` / allow |
| `tools/post-execute` | waterfall | `block`（纠错反馈）/ allow |
| `tools/result` | emit | 仅观察（审计日志） |
| `agent/pre-step` | waterfall | `reject` / allow |
| `agent/turn-stopping` | awaited 通知 | `block`/`ask` 以原因 steer 强制续跑（每轮有上限） |
| `agent/session-start` | emit | 仅观察（审计日志；无法拦截启动） |
| `subagent/start` / `subagent/end` | emit | 仅观察（审计日志；以子会话 id 关联） |
| `ctx.tools.guard()` | 同步不变量 | 仅 `deny`（只走规则阶段），在整个 pre-execute waterfall 之后 |

- 在 `tools/pre-execute` 上，`ask` 映射为 `{ kind: 'ask', reason }`，走 harness 原生审批服务（`ctx.get('approval')`）；审批服务未装配时，harness 自动把 `ask` 降级为 `deny`。
- `agent/pre-step` 与 `tools/post-execute` 没有审批缝，`ask` 分别降级为 `reject` 与 `block`。
- 在 `agent/turn-stopping` 上 harness 没有终止原语，因此阻断判决通过 `agent.steer` 以原因强制续跑（与 Claude Code `Stop` 钩子桥同一通道）。守卫对每个（会话， turn）的连续 steer 上限为 3，超过后降级为仅审计（harness 的 stop-loop guard 尚未发布）。
- `ctx.tools.guard()` 通过 harness 的单调 guard API 注册：它在所有 `tools/pre-execute` 监听器之后运行、只能拒绝、不受监听器顺序影响。该 seam 是同步的，因此只走规则阶段。

**单钩子契约**：策略编辑器强制每条策略只绑定一个 hook，没有 `*`（全 hook）选项，也不支持多选。`ask` 被锁定在 `tools/pre-execute`（唯一有审批缝的 hook），对其他 hook 选择 `ask` 会被 UI 阻止、被保存接口拒绝（否则会静默降级为 block/reject）。

**面板绑定面**：策略编辑器提供上述全部九个原生 seam。仅观察 seam 与 `ctx.tools.guard` 不变量带有悬浮提示，说明判决在该处的实际效果。审查模板（模型阶段）与基线作用域提供同样的九 seam 绑定面，且支持多选：一条模板会加入其勾选的每条 hook 链。在仅观察 seam 上注册的是完整管线（规则 + 模型），审查照常运行、判决只记入审计行而不中断运行（与绑定到这些 seam 的策略行为一致）；`ctx.tools.guard` 是同步且仅规则阶段，模型绑定在此不生效（悬浮提示会说明）。

## 决策语义

1. 按事件 `eventType` 选出 `hooks` 匹配且 `enabled` 的策略（hook 选择器支持精确 seam 名、`*` 与 glob；面板只写单 hook 策略）。
2. 按 `priority` 降序遍历（默认 100，同优先级按声明顺序）。
3. 策略内任意一条 rule 命中即策略命中（OR 语义）。
4. 命中即返回该策略的 `action`；全部未命中则默认 `allow`。
5. 引擎异常绝不抛到 hook 路径上；按 `failOpen`（默认 `true`）降级为 allow 或 block。

## 审查链路（规则 → 模型，两段均可插拔）

守卫链路为 `hook → 规则 → 模型 → 判决`（`src/model-review.ts`）。两个阶段相互独立，均可在"Security Guard"设置分区开关：

- **规则阶段**（`engine.ts`，`rulesEnabled` 偏好，默认开）：同步、确定性强、毫秒级。`setRulesEnabled(false)` 会短路 `decide()` 直接放行，不再进入模型阶段。
- **模型阶段**（`model-review.ts`，`modelReview` 偏好，默认关）：在规则阶段之后、按模板绑定的 seam 逐个运行，用渲染好的审查提示词调用大模型，并把输出解析为同样的四种动作（`allow` / `warn` / `ask` / `block`）。

模型阶段通过**审查模板**运行。内置三条（`audit-prompts.ts`）：恶意意图检测绑定 `agent/pre-step`，风险指令检测与意图偏离检测绑定 `tools/pre-execute`。基线模板在面板上是只读卡片（仅启用开关可改）；自定义模板经多选绑定一个或多个 hook，排在基线模板之后执行，并可用 `action` 字段限制本模板能给出的最重判决。

模型阶段依赖的东西都收在接缝后面，替换接线不需要动引擎：

- `ModelVerdictParser`（`createModelVerdictParser` 返回组合解析器，能读内置模板的 JSON 与两行纯文本判决格式，最后兜底通用"取最后一个 JSON 对象"）：模型输出 → 判决。
- `ModelCaller`：会话模式下 `SessionModelCaller` 经 `ctx.llm` 复用会话当前模型；自定义模式下按 `modelReview.protocol` 选择三种协议之一访问专用端点：`openai-chat`（`/chat/completions`，默认）、`openai-responses`（Responses API）、`anthropic`（Messages API）。`createModelCaller` 是后续接入重试/流式/其他厂商的替换点。
- `mergeVerdicts(rule, model)` 是唯一的纯合并策略，语义为**最严者胜**（`block > ask > warn > allow`）：规则判决是下限，模型只能加重、不能放宽；模型给出更重判决时，采用模型的判决与理由。两阶段都缺失则放行。模板间判决按同样方式合并，`block` 会短路剩余模板。

fail-open 姿态贯穿全链路：模型阶段缺失或关闭、caller 超时（`timeoutMs`，默认 12000 ms）、输出无法解析、会话路由不可用，一律降级为规则判决。**短路**：`block` 已是模型可能给出的最重判决，因此规则判 `block` 时直接跳过模型调用；只有规则判 `ask`/`warn`/`allow`（或规则阶段关闭）才会咨询模型，而模型最多只能确认或加重。

会话模式从会话日志解析模型路由。会话第一条请求时路由可能还没写进日志，该事件会被跳过并记为 `status: 'skipped'`。打开 `modelReview.makeupReview`（默认关，仅会话模式）后，被跳过的事件进入一个有界内存队列，等路由出现后补审。

每次模型审查尝试都会以 `kind: 'model'` 行追加到审计文件（provider、渲染后的请求、原始响应、耗时、状态），Security Review 页签因此能看到模型阶段的完整过程。`allow` 行遵循与合并判决相同的"记录 allow 判决"开关；`error` 与 `skipped` 行始终落盘。

模型阶段会用面板语言写审查理由（`lang` 传给该阶段）；存储理由中的固定判决标签由 adapter 在读取时本地化。

Demo API-key 说明：`modelReview.apiKey` 明文存放在 settings 文档中。后续迭代可经 `createModelCaller` 接缝把密钥挪进 harness `credentials` 服务。

## 面板生命周期

面板是**静态 web 插件**，不是 `dynamicCordisRunner` 插件。host 侧注册 `/guard/api/*` 路由（`guard-api.ts`），client 侧是 `dsh.client` bundle（`src/client`，由 tsdown 编译为 `lib/client.js`）。无进程级审批弹窗、无动态 runner 会话锚定，client 不会离开它的锚点会话。

- **头部工具位**：client 注册一个会话级插槽 `conversation.session.header.utilities`，即每个打开会话头部一个紧凑盾牌按钮（含实时拒绝数徽标），点击打开面板。按钮仅在 `showHeaderButton` 偏好开启时存在，切换设置会实时挂载/卸载该座位。特意**不用** `sidebar.footer.action`：那一行是全宽水平 flex 行，已被内置 Cordis 面板入口占满，再加一个全宽项会被推出侧边栏并被应用边框裁剪。
- **Security Review 页签**：client 还在 `conversation.view` 环（Trajectory 旁）注册会话级页签，`showSessionTab` 偏好开启时存在。每个会话各自一个页签，只显示该会话判决（含子 agent 会话），打开时每 4 秒轮询。两个开关都在"Security Guard"设置分区，旁边还有总开关（`guardEnabled`）、规则阶段开关（`rulesEnabled`）与 allow 记录开关（`recordAllow`），全部即时生效、无需刷新。若当前激活页签被移除，会话壳回退到默认 Chat 视图。

### 面板 API 安全

`/guard/api/*` 同时承载会话明文与控制能力（策略表替换、总开关），因此加了防护：

- **仅限回环 Host**（含正确的 IPv6 `[::1]` 解析与 127.0.0.0/8 段），并集上显式 `webRuntime.trustedHosts` 白名单（全接口装配时按绑定推导出的局域网字面量，加上 `dsh web --trusted-host` 指定的授权主机）。有白名单时回环依然放行，所以白名单只会放宽防线、不会收紧；伪造/重绑定的 `Host` 一律拒绝。
- 拒绝 `Sec-Fetch-Site: cross-site` 与不匹配的 `Origin`（Origin 主机名必须回环或在白名单内，且与请求 Host 一致）。
- 变更类请求必须带 `Content-Type: application/json`（阻断 CORS 安全列表中的"简单请求"CSRF）。
- 每次变更额外要求进程内随机生成的 CSRF 令牌（以 `SameSite=Strict` cookie 下发，double-submit 校验），跨站页面永远带不上它。
- `webServer.host` 非 `127.0.0.1` 时，只有存在 `trustedHosts` 白名单才注册面板 API；没有白名单则**完全不注册**（网络侧不暴露任何会话明文或控制路由）。

### 判决审计文件

判决写入插件自有审计文件 `$DSH_HOME/agent-security-guard/verdicts.jsonl`（JSONL，`audit.ts`；追加式，`allow` 默认不落盘）。面板轮询该文件，并把每条记录与活跃会话上下文关联（工具调用/结果、逐步提示词、审批结果）。每条记录携带持久化元信息（session / turn / step / call id / policy / time）；工具判决同时持久化工具名与 call id，`agent/pre-step` 判决持久化记录时检查到的装配提示词内容。详情字段有界（每个约 4 KB）。模型审查尝试以 `kind: 'model'` 行写入同一文件。文件跨重启存活；已停止的会话仍显示其存储的记录（只是没有关联细节）。文件增长有 4 MB 上限：超过后压缩重写、仅保留较新的一半，面板内也可清空。

### 在线配置文件总线

在线编辑走文件总线。插件不修改 harness，也不新增 agent 可达的攻击面（client 侧是固定字符串，模型不可达）：

```
$DSH_HOME/agent-security-guard/          # DSH_HOME 默认为 ~/.dsh
├── ui-policies.json   # 面板保存时由 host 侧写入（主插件只读，watch 热加载）
├── effective.json     # 当前生效表的镜像，由主插件写入（面板只读展示）
└── verdicts.jsonl     # 插件自有判决审计文件，由 audit.ts 写入（面板折叠后展示）
```

语义：

- `ui-policies.json` 存在且合法 → **整体替换** cordis.yml 策略表（不合并）；不存在 → 使用 cordis.yml 基线。
- "恢复 cordis.yml 基线" = 写 `{"v":1,"reset":true}` 标记；store 恢复基线后删除该文件。
- 文件损坏 / schema 非法 / 语义非法 → 保留最后一份有效表；错误写入 `effective.json.error` 并在面板展示；守卫不停止。
- 保存后大约 1 秒内生效（watch 轮询间隔），无需重启。

手改 `ui-policies.json` 完全支持，语义相同，面板只是它的编辑器。格式为 `{v: 1, policies: [...]}`，`policies` 与 cordis.yml 的 `policies` 字段同构。

> 权限说明：UI 操作员由此获得"修改本机运行时护栏"的能力，等同于他们已有的权限（本来就能改 cordis.yml、审批动态插件）。若威胁模型要求操作员不能改规则，就不要在装配层注册面板，或将读写插件拆分、分别独立审批。

### 语言偏好

插件注册了 `agent-security-guard` 设置命名空间，DSH Settings 壳据此渲染语言选择器（`auto` / `zh` / `en`）。面板 client 会经 `POST /guard/api/lang/resolved` 把当前 DSH 语言回报给 host，因此 `auto` 跟随 DSH 语言，而不是直接落到英文。没有 settings 服务的部署回退到 schema 默认值（`auto`，英文）。

解析出的语言同时决定判决理由的语言：规则理由以英文串存储，配合 `adapter.ts` 中的中文翻译表（`REASON_ZH`）在展示时本地化；模型阶段则直接要求模型用面板语言书写理由。
