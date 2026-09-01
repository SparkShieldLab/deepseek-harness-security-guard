# 架构说明

设计边界、源码结构、Hook 点、决策语义与审查面板生命周期。配置参考见 [policy-table.md](./policy-table.zh-CN.md)。

## 设计边界

- **本地有界同步决策**：`engine.ts` 不做任何外部调用。判决路径对单事件有界：`regex` 算子会拒绝已知灾难性回溯的模式（嵌套/交替量词组，含 `{n}` 重复形态）并限制输入长度，因此在已覆盖形态下同步决策不会冻结 harness 事件循环（S1）；非常规回溯形态超出当前审查面。
- **仅本地规则**：在线决策（远程策略服务）不在本插件范围内。需要时可在 `adapter.ts` 中扩展 `engine.decide` 调用点。
- **不包含沙箱 / 心跳 / 元数据上报**：本插件只做本地规则决策，不含这些能力。
- **不写 harness 会话日志**：判决只写入插件自有的审计文件（`verdicts.jsonl`），绝不使用 `feedback/record`——harness 遥测层把一条已提交的 `feedback/record` 当作上传会话内容的同意凭据（B1）。
- **面板 API 仅限回环**：只有 webServer 绑定 `127.0.0.1` 时才注册 `/guard/api/*` 路由；非回环绑定则完全不注册任何面板路由。

## 目录结构

包分为两半：**host 半**（Node，运行在 harness 进程内）与 **client 半**（浏览器 bundle，通过 package.json 的 `dsh.client.inject` 由 DSH web 壳加载）。

```
src/
├── index.ts        # 插件入口：name / Config / apply；串联 engine、监听器、文件总线、面板 API
├── config.ts       # Config schema（schemastery）+ 语义校验 + UiPolicyTable
├── types.ts        # GuardPolicy / GuardRule / GuardEvent / GuardDecision
├── engine.ts       # GuardEngine：规则匹配、优先级、failOpen；setPolicies 热替换
├── policy-store.ts # 策略文件总线：watch + 热替换 + effective.json 镜像
├── guard-api.ts    # host 侧 /guard/api/* 路由
├── adapter.ts      # harness 事件 -> GuardEvent；判决 -> harness 决策；特征合并
├── features.ts     # 威胁特征提取（静态 / 有状态 / 工具结果）
├── intent.ts       # 用户意图攻击扫描（block / warn 风险特征）
├── patterns.ts     # 威胁模式库
├── secrets.ts      # 已观测密钥检测
├── state-store.ts  # 会话/轮次状态（滑动 TTL；循环计数、信号、密钥，LRU 上限）
├── base-policies.ts# 内置基线策略（27 条，优先级 50）
├── normalize.ts    # 有界文本归一化（raw / normalized / compact）
├── decode.ts       # 有界 base64/hex/UTF-16LE 载荷解码（深度 2，可打印过滤）
├── prompt-guard.ts # 系统提示词安全段落构造器
└── audit.ts        # 判决写入插件自有的本地 JSONL 审计文件
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
- 在 `agent/turn-stopping` 上 harness 没有终止原语，因此阻断判决通过 `agent.steer` 以原因强制续跑（与 Claude Code `Stop` 钩子桥同一通道）。守卫对每个（会话， turn）的连续 steer 上限为 3，超过后降级为仅审计——harness 的 stop-loop guard 尚未发布。
- `ctx.tools.guard()` 通过 harness 的单调 guard API 注册：它在所有 `tools/pre-execute` 监听器之后运行、只能拒绝、不受监听器顺序影响。该 seam 是同步的，因此只走规则阶段。

**单钩子契约**：策略编辑器强制每条策略只绑定一个 hook——没有 `*`（全 hook）选项，也不支持多选。`ask` 被锁定在 `tools/pre-execute`（唯一有审批缝的 hook），对其他 hook 选择 `ask` 会被 UI 阻止、被保存接口拒绝（否则会静默降级为 block/reject）。历史配置中仍含 `*` 或多 hook 的可以继续加载（引擎保持兼容），下次从面板保存时归一化为单个 hook。

**旧版 v0.1.x hook 名**（`before_tool_call`、`tool_result_persist`、`after_tool_call`、`before_prompt_build`）在所有读取路径（策略表、偏好设置、审计行）中仍被接受并归一化为上表的原生 seam；所有写入路径（面板保存）输出原生命名。

**面板绑定面**：策略编辑器提供上述全部九个原生 seam。仅观察 seam 与 `tools/guard` 不变量带有悬浮提示，说明判决在该处的实际效果。审查模板（模型阶段）与基线作用域提供同样的九 seam 绑定面，且支持多选：一条模板会加入其勾选的每条 hook 链。在仅观察 seam 上注册的是完整管线（规则 + 模型），审查照常运行、判决只记入审计行而不中断运行——与绑定到这些 seam 的策略行为一致；`tools/guard` 是同步且仅规则阶段，模型绑定在此不生效（悬浮提示会说明）。

## 决策语义

1. 按事件 `eventType` 选出 `hooks` 匹配且 `enabled` 的策略（引擎为兼容历史文件支持 `*`/glob；面板只写单 hook 策略）。
2. 按 `priority` 降序遍历（默认 100，同优先级按声明顺序）。
3. 策略内**任意一条 rule 命中即策略命中**（OR 语义）。
4. 命中即返回该策略的 `action`；全部未命中 → 默认 `allow`。
5. 引擎异常绝不抛到 hook 路径上；按 `failOpen`（默认 `true`）降级为 allow 或 block。

## 面板生命周期

面板是**静态 web 插件**，不是 `dynamicCordisRunner` 插件。host 半注册 `/guard/api/*` 路由（`guard-api.ts`），client 半是 `dsh.client` bundle（`src/client`，由 tsdown 编译为 `lib/client.js`）。无进程级审批弹窗、无动态 runner 会话锚定，client 不会离开它的锚点会话。

- **头部工具位**：client 注册一个会话级插槽 `conversation.session.header.utilities`——每个打开会话头部一个紧凑盾牌按钮（含实时拒绝数徽标），点击打开面板。特意**不用** `sidebar.footer.action`：那一行是全宽水平 flex 行，已被内置 Cordis 面板入口占满，再加一个全宽项会被推出侧边栏并被应用边框裁剪。
- **Security Review tab**：client 还在 `conversation.view` 环（Trajectory 旁）注册会话级 tab，`showSessionTab` 偏好开启时存在（在"Security Guard"设置分区切换）。每个会话各自一个 tab，只显示该会话判决，打开时每 4 秒轮询。若当前激活 tab 被移除，会话壳回退到默认 Chat 视图。

### 面板 API 安全

`/guard/api/*` 同时承载会话明文与控制能力（策略表替换、总开关），因此加了防护（B2）：

- **仅限回环 Host**（含正确的 IPv6 `[::1]` 解析与 127.0.0.0/8 段）；伪造/重绑定的 `Host` 一律拒绝；
- 拒绝 `Sec-Fetch-Site: cross-site` 与不匹配的 `Origin`；
- 官方变更类请求必须带 `Content-Type: application/json`（阻断 CORS 安全列表中的"简单请求"CSRF）；
- 每次变更额外要求进程内随机生成的 CSRF 令牌（以 `SameSite=Strict` cookie 下发给同源页面）——跨站页面永远带不上它；
- `webServer.host` 非 `127.0.0.1` 时，**完全不注册**面板 API（网络侧不暴露任何会话明文或控制路由）。

### 判决审计文件

判决写入插件自有审计文件 `$DSH_HOME/agent-security-guard/verdicts.jsonl`（JSONL，`audit.ts`；追加式、有大小上限、`allow` 默认不落盘）。面板轮询该文件，并把每条记录与活跃会话上下文关联（工具调用/结果、逐步提示词、审批结果）。文件跨重启存活；已停止的会话仍显示其存储的记录（只是没有关联细节）。

### 在线配置文件总线

在线编辑走文件总线——不修改 harness，也不新增 agent 可达的攻击面（client half 是固定字符串，模型不可达）：

```
$DSH_HOME/agent-security-guard/          # DSH_HOME 默认为 ~/.dsh
├── ui-policies.json   # 面板保存时由 host 半写入（主插件只读，watch 热加载）
├── effective.json     # 当前生效表的镜像，由主插件写入（面板只读展示）
└── verdicts.jsonl     # 插件自有判决审计文件，由 audit.ts 写入（面板折叠后展示）
```

语义：

- `ui-policies.json` 存在且合法 → **整体替换** cordis.yml 策略表（不合并）；不存在 → 使用 cordis.yml 基线。
- "恢复 cordis.yml 基线" = 写 `{"v":1,"reset":true}` 标记；store 恢复基线后删除该文件。
- 文件损坏 / schema 非法 / 语义非法 → 保留最后一份有效表；错误写入 `effective.json.error` 并在面板展示；守卫不停止。
- 保存后大约 1 秒内生效（watch 轮询间隔），无需重启。

手改 `ui-policies.json` 完全支持，语义相同——面板只是它的编辑器。格式为 `{v: 1, policies: [...]}`，`policies` 与 cordis.yml 的 `policies` 字段同构。

> 权限说明：UI 操作员由此获得"修改本机运行时护栏"的能力，等同于他们已有的权限（本来就能改 cordis.yml、审批动态插件）。若威胁模型要求操作员不能改规则，就不要在装配层注册面板，或将读写插件拆分、分别独立审批。

### 语言偏好

插件注册了 `agent-security-guard` 设置命名空间，让 DSH Settings 壳能渲染语言选择器。没有 settings 服务的部署不会渲染该选项，面板回退到 schema 默认值（`auto`）。