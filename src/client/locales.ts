/**
 * Minimal zh/en copy for the Security-Guard Review panel and its settings
 * section. The copy follows the DSH i18n shape: the client apply attaches the
 * DSH locale service through {@link attachLocale}, and the preference tri-state
 * (auto / zh / en) is resolved by {@link effectiveLocale}. `'auto'` (the
 * default) follows the Host-backed active locale and switches live, while an
 * explicit choice forces the panel into that language. The preference itself
 * is persisted through the plugin's own `/guard/api/lang` route into the DSH
 * settings namespace (`agent-security-guard`); {@link subscribePreference}
 * lets the panel and the settings section re-render on every write.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/client/locales
 */

import type { GuardLocale, ModelReviewPrefsLike } from './api.ts'

/** The zh dictionary (the canonical key set; `en` is type-checked against it). */
export const zh = {
  // ── panel chrome ──
  headerButton: '安全守卫',
  panelTitle: '安全守卫审查',
  closePanel: '关闭',
  summary: '已拦截 {deny} · 待确认 {ask} · 已警告 {warn} · 已放行 {pass}',

  // ── tabs ──
  tabLog: '判决记录',
  tabConfig: '规则配置',
  tabConfigStatusOn: '规则审查已启用',
  tabConfigStatusOff: '规则审查已停用',

  // ── filters ──
  filterAll: '全部',
  filterDeny: '已拦截',
  filterAsk: '待确认',
  filterWarn: '已警告',
  filterAllow: '已放行',
  filterTitle: '仅显示{label}判决',

  // ── actions / status ──
  loading: '加载中…',
  refresh: '刷新',
  clearLog: '清空日志',
  clearLogTitle: '清空审查日志中的所有判决',
  countBlocked: '{n} 个已拦截',
  noVerdicts: '暂无安全守卫判决记录',
  noFilterWindow: '当前窗口内没有{label}判决',
  noHookMatches: '没有绑定 {hook} 的策略',
  chainObserveOnly: '仅观察',
  scTitle: '审查链路',
  scGuardOff: '守卫总开关已停用：链路不生效，所有事件直接放行',
  scStageRules: '规则 {count} 个',
  scNoRules: '无规则',
  scRulesOff: '规则阶段已关',
  scModelCount: '模型 {count} 个',
  scBaseline: '基线',
  scModelOff: '模型阶段已关',
  scNoBinding: '未绑定模板',
  hookDescSessionStart: '会话启动时触发一次：适合初始化检查与会话级策略',
  hookDescPreStep: '每个推理步骤执行前触发：可拦截或转人工确认该步骤',
  hookDescPreExecute: '工具调用执行前触发：审查工具名与入参，命中即拦截或转人工',
  hookDescGuard: '工具执行中的显式检查点（ctx.tools.guard()）',
  hookDescPostExecute: '工具调用执行完毕后触发：审计收尾与副作用',
  hookDescResult: '工具结果返回给模型前触发：审查结果内容',
  hookDescTurnStopping: '一轮回复结束前触发：审查最终输出',
  hookDescSubagentStart: '子代理启动时触发',
  hookDescSubagentEnd: '子代理结束时触发',
  scRulesCardTitle: '规则阶段：按优先级依次匹配下方策略，命中即产出判决；block 命中时短路模型阶段',
  scModelCardTitle: '模型阶段：下方模板拼装为一次模型审查调用，判决叠加在规则之上（只能更严，不能放宽）',
  scNoId: '（未命名）',
  policyTitleAction: '动作：{action} · 优先级 {priority}',
  policyTitleRules: '{count} 条规则',
  policyTitleMessage: '判决提示：{message}',
  templateTitleHooks: '绑定：{hooks}',
  templateTitlePrompt: '提示词',
  templateTitleDefaultPrompt: '（空 = 内置默认模板）',
  scBaselineTitle: '内置默认审查模板：在该 hook 的模板链中最先运行',

  // ── verdict rows ──
  outcomeBlocked: '已拦截',
  outcomeAsk: '待确认',
  outcomeWarned: '已警告',
  outcomeAllowed: '已放行',
  approvalAllowedOnce: '已通过',
  approvalRejected: '已拒绝',
  approvalCancelled: '已取消',
  approvalUnavailable: '审批不可用',
  approvalTitle: '审批结果：{outcome}',
  noSeamBadge: '无审批通道→拒绝',
  noSeamTitle: '该 hook 没有审批通道，ask 已自动降级为拒绝/拦截（未弹窗等待人工确认）',
  rowTitle: '点击展开',
  showDetails: '显示工具参数/提示词内容',
  hideDetails: '隐藏详情',
  showDetailsAria: '显示详情',
  hideDetailsAria: '隐藏详情',
  metaTurn: '第 {n} 轮',
  metaStep: '第 {n} 步',
  metaCall: '调用 {id}',
  metaPolicy: '策略 {id}',
  metaApproval: '审批：{outcome}',
  noDetail: '此判决未记录详情',
  labelArguments: '参数',
  labelResult: '结果',
  labelPrompt: '提示词',

  // ── review table (conversation.view tab) ──
  thTime: '时间',
  thOutcome: '结果',
  thType: '类型',
  thHook: '钩子',
  thTool: '工具',
  thMessage: '信息',
  typeRule: '规则',
  typeModel: '模型',
  modelError: '错误',

  // ── config page ──
  configCounts: '共 {count} 个策略（{baseCount} 条基线 · {customCount} 条自定义）',
  syncError: '上次同步未生效：{error}',
  noPoliciesBanner: '当前没有任何生效策略——默认放行所有工具调用与提示词。请至少添加一条策略以强制守卫规则。',
  noPoliciesNote: '还没有策略——使用“+ 添加策略”创建你的第一条规则。',
  addPolicy: '+ 添加策略',
  jsonView: 'JSON 视图',
  applyJson: '应用 JSON',
  jsonHint: '粘贴一个策略数组或完整的 {v:1, policies:[...]} 表格，然后点击“应用 JSON”载入表单。保存始终写入表单内容。',
  save: '保存',
  saving: '保存中…',
  reload: '重新加载',
  saved: '已保存',
  saveFailed: '保存失败',
  clearNote: '判决日志已清空',
  clearFailed: '清空失败：',
  configReadFailed: '读取当前生效配置失败',
  jsonApplyFailed: 'JSON 应用失败：',
  groupBaseline: '内置基线策略',
  policiesCount: '{count} 个策略',
  showBaseline: '显示基线',
  hideBaseline: '隐藏基线',
  deleteConfirm: '确定删除策略“{id}”？',

  // ── policy editor ──
  badgeBaseline: '基线',
  badgeCustom: '自定义',
  enabledTitle: '启用',
  policyIdPlaceholder: '策略 ID',
  actionAllow: '允许',
  actionBlock: '拦截',
  actionAsk: '询问',
  actionWarn: '警告',
  collapseTitle: '收起',
  expandTitle: '展开',
  baseMetaTitle: '内置基线策略只读：仅启用开关可修改，不能编辑或删除。如需定制，请复制为自定义策略。',
  deletePolicy: '删除策略',
  labelHooks: '钩子',
  hookNote: '单选：每个策略只监听一个钩子。',
  askHookNote: 'ask 仅支持 tools/pre-execute（唯一有审批通道的钩子），其他钩子已锁定（会退化为 block/reject）。',
  hookLockedTitle: '该钩子没有审批通道：ask 在此会自动退化为 block/reject',
  hookObserveOnlyTitle: '仅观察 seam：判决只记入审计日志，不会中断运行',
  hookGuardTitle: '单调不变量（ctx.tools.guard()）：只有 block 生效（拒绝），且只走规则阶段',
  labelPriority: '优先级',
  labelMode: '模式',
  modeHint: '运行模式：protect 按配置执行动作（block/ask 真正阻止该步骤）；monitor 仅记录——block/ask 降级为 warn 并放行事件。先用 monitor 试运行新策略再正式启用。留空继承全局模式。',
  modeDefault: '引擎默认',
  modeProtect: '防护',
  modeMonitor: '观测',
  labelMessage: '消息（策略触发时显示）',
  messagePlaceholder: '可选原因',
  labelRules: '规则——任一规则命中即触发策略',
  addRule: '+ 添加规则',

  // ── rule editor: field-selector groups (optgroup labels) ──
  groupUniversal: '通用',
  groupToolCall: '工具调用',
  groupToolResult: '工具结果',
  groupPromptContent: '提示词 / 内容',

  // ── rule row ──
  fieldPlaceholder: '— 字段 —',
  fieldSelectTitle: '选择已知字段，或选择“✎ 自定义…”使用任意字段名',
  outOfScope: '{field} — 超出作用域',
  customOption: '✎ 自定义…',
  fieldEmptyHint: '选择字段以过滤工具调用或提示词。悬停此处查看说明。',
  fieldCustomHint: '自定义字段——无内置说明；引擎会根据事件负载解析。',
  customFieldPlaceholder: '自定义字段名',
  customFieldHint: '自定义字段名会针对拍平后的事件负载解析（先 data 后 context）。',
  valuePlaceholder: '— 值 —',
  valueEnumHintSuffix: '选择候选值，或选择“✎ 自定义…”',
  customValuePlaceholder: '自定义值',
  valueInputHintIn: '逗号分隔，如 bash, sh',
  valueInputHintMatches: '通配符模式，如 ~/.ssh/*',
  valueInputHintText: '文本 / true / 123',
  removeRule: '删除规则',

  // ── field hints (field tooltips) ──
  hint_eventType: '产生该事件的安全守卫钩子',
  hint_agentId: '发起调用的代理/会话 id',
  hint_agentType: '代理角色（预留）',
  hint_sessionId: '事件所属会话 id',
  hint_turn: '轮次编号（整数）',
  hint_step: '步骤编号（整数）',
  hint_raw: '以 JSON 形式匹配完整原始事件负载，例如正则 "\\\"command\\\": \\\"rm -rf\\\"" 或 contains "rm -rf"',
  hint_toolName: '代理即将调用的工具',
  hint_arguments: 'harness 传入的原始工具参数',
  hint_command: '命令的子串；支持 * 通配符，如 ls* 匹配带任意参数的命令',
  hint_highRisk: '启发式高风险调用标记',
  hint_obfuscated: '混淆命令/编码负载',
  hint_deleteOutsideWorkspace: '删除工作区之外的目标',
  hint_outbound: '沙箱之外的网络访问',
  hint_secretRef: '调用涉及凭据引用',
  hint_transformSignal: '数据转换启发式触发',
  hint_encodedHighRisk: '编码形式的高风险模式',
  hint_protectedPathHit: '调用触及受保护路径',
  hint_scriptArtifactPath: '生成的脚本产物路径',
  hint_scriptArtifactHash: '生成的脚本产物 djb2 哈希',
  hint_scriptArtifactRisk: '生成产物将执行代码',
  hint_observedSecrets: '调用中观察到的疑似机密值',
  hint_repeatExceeded: '迭代预算超限',
  hint_toolResultText: '工具输出原始文本',
  hint_toolResultFlags: '工具结果元数据标记',
  hint_toolResultSuspicious: '工具输出疑似注入指令',
  hint_specialTokensRemoved: '从结果中剥离的提示注入标记',
  hint_exfilChain: '检测到工具结果泄漏链',
  hint_artifactExecutionRisk: '生成产物将执行代码',
  hint_content: '事件携带的文本内容（提示词 / 停止前最终输出 / 子代理输出）',
  hint_userIntentRisk: '模型意图风险分类器输出',

  // ── settings section ──
  settingsNav: '安全守卫',
  settingsIntro: '管理安全守卫审查面板的显示、语言偏好与全局防护开关。',
  langLabel: '语言',
  langDefault: '跟随应用语言',
  langZh: '中文',
  langEn: 'English',
  langDefaultDesc: '跟随 DSH 当前界面语言',
  langZhDesc: '以中文显示安全守卫面板',
  langEnDesc: '以英文显示安全守卫面板',
  showHeaderLabel: '显示右上角盾牌按钮',
  showHeaderDesc: '在会话窗口右上角显示安全守卫盾牌按钮。关闭后盾牌按钮立即隐藏。',
  guardEnabledLabel: '启动防护插件',
  guardEnabledDesc: '关闭后安全守卫完全停用：不再拦截、审批，也不再记录判决日志。',
  recordAllowLabel: '记录“已放行”判决',
  recordAllowDesc: '开启后，所有“已放行”的判决也会写入审计日志（默认仅记录拦截/询问/警告）。',

  // ── settings section: review chain (rules + model stages) ──
  chainTitle: '审查链路',
  chainDesc: '守卫链为「hook → 规则 → 模型 → 判决」，两个阶段可插拔、可独立开关；模型审查叠加在规则审查之上，输出 allow / warn / ask / block 四种判决。',
  // ── settings section: interface & language group (display-only toggles) ──
  uiTitle: '界面与语言',
  // ── settings section: debug group (audit-troubleshooting toggles) ──
  debugTitle: '调试',
  debugDesc: '排查与审计相关选项；默认关闭，避免日志膨胀。',
  rulesEnabledLabel: '启用规则审查',
  rulesEnabledDesc: '规则审查是守卫链的第一阶段（同步、毫秒级、确定性）。关闭后规则引擎直接放行，模型审查仍可独立生效。',
  modelReviewEnabledLabel: '启用模型审查',
  modelReviewEnabledDesc: '模型审查是守卫链的第二阶段：调用大模型对 hook 内容二次审查并给出判决。超时或解析失败时自动回退到规则判决。',
  modelReviewModeLabel: '审查模型来源',
  modelReviewModeDesc: '选择模型审查使用的模型来源。',
  modelReviewModeSession: '复用会话模型',
  modelReviewModeSessionDesc: '直接使用当前会话正在使用的模型（走会话模型路由），无需额外配置。',
  modelReviewReuseTokenConfirmTitle: '开启复用将在每次审查时消耗额外 token',
  modelReviewReuseTokenConfirm: '选择「复用会话模型」后，模型审查将调用当前会话的大模型进行二次审查，每次审查都会产生额外的 token 使用（计入你的模型配额/费用）。确定要继续吗？',
  modelReviewModeSessionTiming: '受时序影响：会话第一次请求的审查会因路由尚未写入而跳过（按规则判决放行），之后自动补审一次并在记录中标注「补审」（仅留痕）。',
  modelReviewMakeupLabel: '补审被跳过的审查事件',
  modelReviewMakeupDesc: '开启后，时序跳过的事件会在路由就绪后自动补审一次（仅留痕）；默认关闭，跳过即止（仍有跳过记录）。仅复用会话模型模式生效。',
  modelReviewModeCustom: '自定义专用审查模型',
  modelReviewModeCustomDesc: '使用独立的大模型端点（OpenAI 兼容 /chat/completions）进行审查，与对话模型隔离，便于审计。',
  modelSkipped: '跳过',
  makeupBadge: '补审 · 仅留痕',
  makeupTitle: '事后补审：该事件在会话第一次请求时因路由未就绪被跳过，路由就绪后自动补审。此记录仅留痕，未参与当时的拦截决策。',
  labelNote: '说明',
  modelReviewBaseUrlLabel: '模型地址 (Base URL)',
  modelReviewBaseUrlPlaceholder: 'https://api.deepseek.com/v1',
  modelReviewBaseUrlResponsesPlaceholder: 'https://api.openai.com/v1',
  modelReviewBaseUrlAnthropicPlaceholder: 'https://api.anthropic.com',
  modelReviewProtocolLabel: '接口协议',
  modelReviewProtocolDesc: '自定义审查端点的调用协议：OpenAI Chat Completions、OpenAI Responses API，或 Anthropic Messages API。',
  modelReviewProtocolChat: 'OpenAI Chat Completions',
  modelReviewProtocolChatDesc: 'OpenAI 兼容 /chat/completions，兼容面最广（DeepSeek 等也适用）。',
  modelReviewProtocolResponses: 'OpenAI Responses API',
  modelReviewProtocolResponsesDesc: 'OpenAI Responses API /responses（输入用 input 字段）。',
  modelReviewProtocolAnthropic: 'Anthropic Messages API',
  modelReviewProtocolAnthropicDesc: 'Anthropic /v1/messages（x-api-key + anthropic-version 头，max_tokens 2048）。',
  modelReviewApiKeyLabel: 'API Key',
  modelReviewApiKeyDesc: '访问自定义审查端点所用的密钥，仅保存在本机插件配置中。',
  modelReviewApiKeyPlaceholder: 'sk-…',
  modelReviewModelLabel: '模型名称',
  modelReviewModelPlaceholder: 'deepseek-chat',
  modelReviewPromptLabel: '审查提示词',
  modelReviewPromptDesc: '只读预览，点「编辑」修改。自定义模板留空则整体跳过，不参与审查。可用占位符：{user_query} {agent_behavior} {hookType} {content} {rulesVerdict} {sessionId}',
  modelReviewPromptEdit: '编辑',
  modelReviewPromptEditDesc: '在弹窗中编辑审查提示词（此处为只读预览）',
  modelReviewPromptView: '查看',
  modelReviewPromptViewModalTitle: '查看提示词：{name}',
  modelReviewPromptModalTitle: '审查提示词',
  modelReviewPromptRestore: '恢复内置模板',
  modelReviewPromptRestoreDesc: '用内置模板替换当前编辑内容',
  modelReviewPromptRestoreConfirm: '当前自定义提示词将被内置模板覆盖，无法撤销。确认恢复？',
  modelReviewPromptClose: '关闭',
  modelReviewPromptDone: '完成',
  modelReviewPromptChars: '当前 {count} 个字符，编辑先存入草稿，点「保存」后生效。',
  modelReviewTimeoutLabel: '调用超时（毫秒）',
  modelReviewTimeoutDesc: '两种模式通用（复用会话模型与自定义端点共用）：单次模型调用的截止时间；超时后本次审查回退到规则判决。审查在守卫判决路径上内联等待，此值即受保护步骤的额外延迟上限。会话/推理模型建议 ≥ 12000（旧默认 3000 会在读取时自动迁移）。',
  modelReviewThinkingLabel: '思考强度（推理链）',
  modelReviewThinkingDesc: '推理力度。OpenAI 协议按所选值附加 reasoning_effort；Anthropic 协议 low/medium/high 开启 thinking 并配 1024/2048/8192 token 预算，「跟随接口默认」不附加任何字段。端点若不接受对应参数会拒绝调用。',
  modelReviewThinkingDefault: '跟随接口默认',
  modelReviewThinkingOff: 'off（禁用推理）',
  modelReviewThinkingLow: 'low（轻量推理）',
  modelReviewThinkingMedium: 'medium（均衡推理）',
  modelReviewThinkingHigh: 'high（深度推理）',

  // ── panel: model-review tab (per-hook prompt templates) ──
  tabModelReview: '模型审查',
  mrTabStatusOn: '模型审查已启用',
  mrTabStatusOff: '模型审查已停用',
  mrTabMode: '模式：{mode}',
  mrTabCounts: '共 {count} 个模板（{baseCount} 个基线 · {customCount} 个自定义）',
  mrTabCustomTitle: '自定义模板',
  mrTabAddTemplate: '+ 添加模板',
  mrTabPriorityHint: '同一 hook 内自上而下按优先级执行，判决取最严；任一模板拦截（block）即短路，不再执行后续模板。',
  mrTabNone: '尚无自定义模板，内置基线模板仍会承担其绑定 hook 的模型审查。',
  mrBaselineGroup: '内置基线模板',
  mrBaselineCount: '{count} 个模板',
  mrBaselineOffHint: '所有基线模板均已关闭：未配置自定义模板的 hook 不会被模型审查。',
  mrBaselineReadonlyHint: '内置基线提示词为只读。如需定制，请将文本复制到自定义模板。',
  mrBaselineMetaTitle: '内置基线模板只读：仅启用开关可修改，不能编辑或删除。如需定制，请复制为自定义模板。',
  mrTabDirty: '有未保存的修改',
  mrTplNamePlaceholder: '模板名称，如「数据泄露审查」',
  mrTplDelete: '删除模板',
  mrTplOrderLabel: '执行顺序',
  mrTplOrderLine: '在 {hook} 链中第 {pos} 个 · 共 {total} 个',
  mrTplNoHooks: '未绑定 hook：此模板不会执行',
  mrTplMoveUp: '上移（提高优先级）',
  mrTplMoveDown: '下移（降低优先级）',
  mrTplPromptEmptyHint: '留空时此模板整体跳过',
  dispositionHint: '该模板允许给出的最严判决：模型给出更严结论时会降级到这里选择的动作（理由保留）；选「允许」则此模板只记录、不处置。',
  dispositionObserveOnly: '绑定的钩子均为仅观测 seam：判决只记入审计日志、不会中断运行，因此处置动作只能选择「允许 / 警告」。',
  mrTplModalTitle: '模板审查提示词',
  metaSource: '来源：{source}',
  metaModelVerdict: '模型判决：{action}',
  metaModelReason: '模型理由',
  metaProvider: '审查模型：{name}',
  metaDuration: '耗时 {ms} ms',
  labelRequest: '请求体',
  labelResponse: '响应体',
  labelError: '错误信息',

  // ── conversation view tab ──
  viewTabGuard: '安全审查',
  tabGuardAria: '显示当前会话的安全守卫判决',
  showTabLabel: '显示会话安全审查标签页',
  showTabDesc: '在会话窗口右侧的标签栏中显示当前会话的防护拦截情况。',

  // ── client-side validation errors (draft editor) ──
  errInArray: '“in” 规则的值必须是数组',
  errValueEmpty: '规则值不能为空',
  errPolicyIdEmpty: '每个策略都需要非空的 ID',
  errPolicyPriority: '策略“{id}”的优先级必须是数字',
  errRuleFieldEmpty: '策略“{id}”有一条规则缺少字段',
  errPolicyNoRules: '策略“{id}”至少需要一条规则',
  errJsonShape: 'JSON 必须是策略数组或 {v:1, policies:[...]} 表格',
} as const

/** The en dictionary (key-set-equal to zh, enforced by the annotation). */
export const en: Record<keyof typeof zh, string> = {
  headerButton: 'Security Guard',
  panelTitle: 'Security Guard Review',
  closePanel: 'Close',
  summary: 'Blocked {deny} · Awaiting confirmation {ask} · Warned {warn} · Allowed {pass}',
  tabLog: 'Verdict Log',
  tabConfig: 'Rule Config',
  tabConfigStatusOn: 'Rule review is on',
  tabConfigStatusOff: 'Rule review is off',
  filterAll: 'All',
  filterDeny: 'Blocked',
  filterAsk: 'Awaiting',
  filterWarn: 'Warned',
  filterAllow: 'Allowed',
  filterTitle: 'Show only {label} verdicts',
  loading: 'Loading…',
  refresh: 'Refresh',
  clearLog: 'Clear log',
  clearLogTitle: 'Clear all verdicts from the review log',
  countBlocked: '{n} blocked',
  noVerdicts: 'No security guard verdicts yet',
  noFilterWindow: 'No {label} verdicts in the current window',
  noHookMatches: 'No policies bound to {hook}',
  chainObserveOnly: 'observe-only',
  scTitle: 'Review chain',
  scGuardOff: 'Guard master switch is off: the chain is inert; everything passes',
  scStageRules: 'Rules: {count}',
  scNoRules: 'no rules',
  scRulesOff: 'rules stage off',
  scModelCount: 'Model: {count}',
  scBaseline: 'baseline',
  scModelOff: 'model stage off',
  scNoBinding: 'no templates',
  hookDescSessionStart: 'Fires once at session start: init checks and session-level policies',
  hookDescPreStep: 'Fires before each reasoning step: block or send the step to human approval',
  hookDescPreExecute: 'Fires before a tool call runs: reviews tool name and arguments; a hit blocks or asks',
  hookDescGuard: 'Explicit in-tool checkpoint (ctx.tools.guard())',
  hookDescPostExecute: 'Fires after a tool call finishes: audits teardown and side effects',
  hookDescResult: 'Fires before a tool result returns to the model: reviews the result content',
  hookDescTurnStopping: 'Fires before a turn ends: reviews the final output',
  hookDescSubagentStart: 'Fires when a subagent starts',
  hookDescSubagentEnd: 'Fires when a subagent finishes',
  scRulesCardTitle: 'Rule stage: the policies below are matched in priority order; a block hit short-circuits the model stage',
  scModelCardTitle: 'Model stage: the templates below are assembled into one model-review call; its verdict stacks on the rules (can only strengthen, never relax)',
  scNoId: '(unnamed)',
  policyTitleAction: 'Action: {action} · priority {priority}',
  policyTitleRules: '{count} rules',
  policyTitleMessage: 'Verdict message: {message}',
  templateTitleHooks: 'Bound: {hooks}',
  templateTitlePrompt: 'Prompt',
  templateTitleDefaultPrompt: '(empty = built-in default template)',
  scBaselineTitle: "Built-in default review template: runs first in this hook's chain",
  outcomeBlocked: 'Blocked',
  outcomeAsk: 'Awaiting confirmation',
  outcomeWarned: 'Warned',
  outcomeAllowed: 'Allowed',
  approvalAllowedOnce: 'Approved',
  approvalRejected: 'Rejected',
  approvalCancelled: 'Cancelled',
  approvalUnavailable: 'No channel',
  approvalTitle: 'Approval result: {outcome}',
  noSeamBadge: 'no approval seam → rejected',
  noSeamTitle: 'This hook has no approval seam, so ask was degraded to reject/block (it did not wait for a human).',
  rowTitle: 'Click to expand',
  showDetails: 'Show tool arguments / prompt content',
  hideDetails: 'Hide details',
  showDetailsAria: 'Show details',
  hideDetailsAria: 'Hide details',
  metaTurn: 'turn {n}',
  metaStep: 'step {n}',
  metaCall: 'call {id}',
  metaPolicy: 'policy {id}',
  metaApproval: 'Approval: {outcome}',
  noDetail: 'No detail recorded for this verdict',
  labelArguments: 'Arguments',
  labelResult: 'Result',
  labelPrompt: 'Prompt',
  thTime: 'Time',
  thOutcome: 'Result',
  thType: 'Type',
  thHook: 'Hook',
  thTool: 'Tool',
  thMessage: 'Info',
  typeRule: 'Rule',
  typeModel: 'Model',
  modelError: 'Error',
  configCounts: '{count} policies in total ({baseCount} baseline · {customCount} custom)',
  syncError: 'Last sync did not take effect: {error}',
  noPoliciesBanner: 'No policies in effect. Every tool call and prompt will be allowed by default. Add at least one policy to enforce guard rules.',
  noPoliciesNote: 'No policies yet. Use “+ Add Policy” to create your first rule.',
  addPolicy: '+ Add Policy',
  jsonView: 'JSON view',
  applyJson: 'Apply JSON',
  jsonHint: 'Paste a policies array or a full {v:1, policies:[...]} table, then Apply JSON to load it into the form. Save always writes the form.',
  save: 'Save',
  saving: 'Saving…',
  reload: 'Reload',
  saved: 'Saved',
  saveFailed: 'Save failed',
  clearNote: 'Verdict log cleared',
  clearFailed: 'Clear failed: ',
  configReadFailed: 'Failed to read the currently effective configuration',
  jsonApplyFailed: 'JSON apply failed: ',
  groupBaseline: 'Built-in baseline policies',
  policiesCount: '{count} policies',
  showBaseline: 'Show baseline',
  hideBaseline: 'Hide baseline',
  deleteConfirm: 'Delete policy "{id}"?',
  badgeBaseline: 'BASELINE',
  badgeCustom: 'CUSTOM',
  enabledTitle: 'Enabled',
  policyIdPlaceholder: 'policy id',
  actionAllow: 'allow',
  actionBlock: 'block',
  actionAsk: 'ask',
  actionWarn: 'warn',
  collapseTitle: 'Collapse',
  expandTitle: 'Expand',
  baseMetaTitle: 'Built-in baseline policies are read-only: only the enabled switch is editable, they cannot be modified or deleted. Copy into a custom policy to customize.',
  deletePolicy: 'Delete policy',
  labelHooks: 'Hooks',
  hookNote: 'Single-select: each policy listens to exactly one hook.',
  askHookNote: 'ask only works on tools/pre-execute (the only hook with an approval seam); other hooks are locked (they would degrade to block/reject).',
  hookLockedTitle: 'No approval seam on this hook: ask would degrade to block/reject',
  hookObserveOnlyTitle: 'Observe-only seam: the verdict is recorded to the audit trail and never interrupts the run',
  hookGuardTitle: 'Monotonic invariant (ctx.tools.guard()): only a block verdict takes effect (deny), rule stage only',
  labelPriority: 'Priority',
  labelMode: 'Mode',
  modeHint: 'Posture: protect runs the action as configured (block/ask really stop the step); monitor records only. Block/ask are downgraded to warn and the event is let through. Use monitor to dry-run a new policy before protecting with it. Leave at engine default to inherit the global posture.',
  modeDefault: 'engine default',
  modeProtect: 'protect',
  modeMonitor: 'monitor',
  labelMessage: 'Message (shown when the policy fires)',
  messagePlaceholder: 'optional reason',
  labelRules: 'Rules: ANY rule matching triggers the policy',
  addRule: '+ Add Rule',
  groupUniversal: 'Universal',
  groupToolCall: 'Tool call',
  groupToolResult: 'Tool result',
  groupPromptContent: 'Prompt / content',
  fieldPlaceholder: '— field —',
  fieldSelectTitle: 'Choose a known field, or pick “✎ custom…” for any field name',
  outOfScope: '{field}: out of scope',
  customOption: '✎ custom…',
  fieldEmptyHint: 'Pick a field to filter tool calls or prompts. Hover here for its description.',
  fieldCustomHint: 'Custom field: no built-in description; the engine resolves it against the event payload.',
  customFieldPlaceholder: 'custom field name',
  customFieldHint: 'Custom field name resolved against the flattened event payload (data first, then context).',
  valuePlaceholder: '— value —',
  valueEnumHintSuffix: 'pick a candidate, or “✎ custom…” for any value',
  customValuePlaceholder: 'custom value',
  valueInputHintIn: 'comma-separated, e.g. bash, sh',
  valueInputHintMatches: 'glob pattern, e.g. ~/.ssh/*',
  valueInputHintText: 'text / true / 123',
  removeRule: 'Remove rule',
  hint_eventType: 'which guard hook produced the event',
  hint_agentId: 'the calling agent / session id',
  hint_agentType: 'agent role (reserved)',
  hint_sessionId: 'session id on the event',
  hint_turn: 'turn number (integer)',
  hint_step: 'step number (integer)',
  hint_raw: 'match against the full raw event payload as JSON, e.g. regex "\\\"command\\\": \\\"rm -rf\\\"" or contains "rm -rf"',
  hint_toolName: 'the tool the agent is about to call',
  hint_arguments: 'raw tool arguments as the harness passed them',
  hint_command: 'substring of the command; matches supports * wildcards, e.g. ls* matches ls with any arguments',
  hint_highRisk: 'heuristic high-risk call flag',
  hint_obfuscated: 'obfuscated command / encoded payload',
  hint_deleteOutsideWorkspace: 'delete targets outside the workspace',
  hint_outbound: 'network access beyond the sandbox',
  hint_secretRef: 'credentials referenced by the call',
  hint_transformSignal: 'data-transformation heuristic fired',
  hint_encodedHighRisk: 'high-risk pattern present in encoded form',
  hint_protectedPathHit: 'call touches a protected path',
  hint_scriptArtifactPath: 'path of a generated script artifact',
  hint_scriptArtifactHash: 'djb2 hash of a generated script artifact',
  hint_scriptArtifactRisk: 'generated artifact would execute code',
  hint_observedSecrets: 'secret-like values observed in the call',
  hint_repeatExceeded: 'iteration budget exceeded',
  hint_toolResultText: 'raw tool output text',
  hint_toolResultFlags: 'tool result metadata flags',
  hint_toolResultSuspicious: 'tool output looks like injected instructions',
  hint_specialTokensRemoved: 'prompt-injection tokens stripped from the result',
  hint_exfilChain: 'tool-result leakage chain detected',
  hint_artifactExecutionRisk: 'generated artifact would execute code',
  hint_content: 'text content the event carries (prompt text / final assistant output / subagent output)',
  hint_userIntentRisk: 'model intent-risk classifier output',
  settingsNav: 'Security Guard',
  settingsIntro: 'Manage the Security Guard review panel display, its language and the global protection switch.',
  langLabel: 'Language',
  langDefault: 'Follow app language',
  langZh: '中文',
  langEn: 'English',
  langDefaultDesc: 'Follow the current DSH interface language',
  langZhDesc: 'Show the Security Guard panel in Chinese',
  langEnDesc: 'Show the Security Guard panel in English',
  showHeaderLabel: 'Show header shield button',
  showHeaderDesc: 'Show the security guard shield button in the session header. Turning it off hides the button immediately.',
  guardEnabledLabel: 'Enable protection plugin',
  guardEnabledDesc: 'When off the guard is fully disabled: no blocking, no approvals and no verdict logging.',
  recordAllowLabel: 'Record allow verdicts',
  recordAllowDesc: 'When on, every allow verdict is also written to the audit log (default records only blocked/asked/warned).',

  // ── settings section: review chain (rules + model stages) ──
  chainTitle: 'Review chain',
  chainDesc: 'The guard chain is `hook → rules → model → verdict`. Both stages are pluggable and independently switchable; the model stage layers on top of the rule stage and outputs the same four verdicts (allow / warn / ask / block).',
  // ── settings section: interface & language group (display-only toggles) ──
  uiTitle: 'Interface & language',
  // ── settings section: debug group (audit-troubleshooting toggles) ──
  debugTitle: 'Debug',
  debugDesc: 'Troubleshooting and audit options; off by default to keep the log small.',
  rulesEnabledLabel: 'Enable rule review',
  rulesEnabledDesc: 'The rule stage is the first link of the guard chain (synchronous, millisecond, deterministic). When off the rule engine allows everything, while the model stage can still run independently.',
  modelReviewEnabledLabel: 'Enable model review',
  modelReviewEnabledDesc: 'The model stage is the second link: it calls a large model to re-review the hook content and produce a verdict. On timeout or unparseable output it falls back to the rule verdict.',
  modelReviewModeLabel: 'Review model source',
  modelReviewModeDesc: 'Choose which model the review stage uses.',
  modelReviewModeSession: 'Reuse the session model',
  modelReviewModeSessionDesc: 'Reuse the model the current session is already using (session model route); no extra config needed.',
  modelReviewReuseTokenConfirmTitle: 'Reuse will consume extra tokens on every review',
  modelReviewReuseTokenConfirm: 'When you pick "Reuse the session model", the model review stage calls the session\'s own large model for a second review, and every review consumes extra tokens (counted against your model quota/costs). Continue?',
  modelReviewModeSessionTiming: 'Timing caveat: the first guarded event of a session races the route logging, so its review is skipped (rule verdict stands) and made up once the route is ready.',
  modelReviewMakeupLabel: 'Make up skipped reviews',
  modelReviewMakeupDesc: 'When on, events skipped on the timing race get one post-hoc review once the route is ready (audit-only); off by default, a skip stays skipped (still recorded). Session mode only.',
  modelReviewModeCustom: 'Dedicated review model',
  modelReviewModeCustomDesc: 'Use a dedicated model endpoint (OpenAI-compatible /chat/completions), isolated from the conversation model for easier auditing.',
  modelSkipped: 'Skipped',
  makeupBadge: 'make-up · audit-only',
  makeupTitle: 'Post-hoc make-up review: this event was skipped when its session dispatched the first request (route not ready yet), then reviewed once automatically. This record is for audit only and took no part in the delivered decision.',
  labelNote: 'Note',
  modelReviewBaseUrlLabel: 'Base URL',
  modelReviewBaseUrlPlaceholder: 'https://api.deepseek.com/v1',
  modelReviewBaseUrlResponsesPlaceholder: 'https://api.openai.com/v1',
  modelReviewBaseUrlAnthropicPlaceholder: 'https://api.anthropic.com',
  modelReviewProtocolLabel: 'Endpoint protocol',
  modelReviewProtocolDesc: 'Wire protocol for the dedicated review endpoint: OpenAI Chat Completions, OpenAI Responses API, or the Anthropic Messages API.',
  modelReviewProtocolChat: 'OpenAI Chat Completions',
  modelReviewProtocolChatDesc: 'OpenAI-compatible /chat/completions; widest compatibility (DeepSeek and friends).',
  modelReviewProtocolResponses: 'OpenAI Responses API',
  modelReviewProtocolResponsesDesc: 'OpenAI Responses API /responses (input field instead of messages).',
  modelReviewProtocolAnthropic: 'Anthropic Messages API',
  modelReviewProtocolAnthropicDesc: 'Anthropic /v1/messages (x-api-key + anthropic-version headers, max_tokens 2048).',
  modelReviewApiKeyLabel: 'API Key',
  modelReviewApiKeyDesc: 'API key for the dedicated review endpoint, kept in the local plugin config only.',
  modelReviewApiKeyPlaceholder: 'sk-…',
  modelReviewModelLabel: 'Model',
  modelReviewModelPlaceholder: 'deepseek-chat',
  modelReviewPromptLabel: 'Review prompt',
  modelReviewPromptDesc: 'Read-only preview — click Edit to change it. A custom template left empty is skipped entirely. Placeholders: {user_query} {agent_behavior} {hookType} {content} {rulesVerdict} {sessionId}',
  modelReviewPromptEdit: 'Edit',
  modelReviewPromptEditDesc: 'Edit the review prompt in a dialog (this box is a read-only preview)',
  modelReviewPromptView: 'View',
  modelReviewPromptViewModalTitle: 'View prompt: {name}',
  modelReviewPromptModalTitle: 'Review prompt',
  modelReviewPromptRestore: 'Restore built-in template',
  modelReviewPromptRestoreDesc: 'Replace the editor content with the built-in template',
  modelReviewPromptRestoreConfirm: 'Your custom prompt will be overwritten by the built-in template, with no undo. Restore?',
  modelReviewPromptClose: 'Close',
  modelReviewPromptDone: 'Done',
  modelReviewPromptChars: '{count} characters; edits stay in the draft until you press Save.',
  modelReviewTimeoutLabel: 'Call timeout (ms)',
  modelReviewTimeoutDesc: 'Shared by both modes (session model and custom endpoint): deadline for one model call; on timeout the review falls back to the rule verdict. The review waits inline in the guard decision path, so this bounds the added latency of a guarded step. Session/reasoning models need ≥ 12000 (the legacy 3000 default migrates automatically on read).',
  modelReviewThinkingLabel: 'Reasoning effort',
  modelReviewThinkingDesc: 'Reasoning strength. OpenAI protocols forward the chosen value as reasoning_effort; Anthropic enables thinking with a 1024/2048/8192-token budget at low/medium/high; "Endpoint default" attaches nothing. Endpoints that reject the field will fail the call.',
  modelReviewThinkingDefault: 'Endpoint default',
  modelReviewThinkingOff: 'Off (no reasoning)',
  modelReviewThinkingLow: 'Low (light reasoning)',
  modelReviewThinkingMedium: 'Medium (balanced reasoning)',
  modelReviewThinkingHigh: 'High (deep reasoning)',

  // ── panel: model-review tab (per-hook prompt templates) ──
  tabModelReview: 'Model Review',
  mrTabStatusOn: 'Model review is on',
  mrTabStatusOff: 'Model review is off',
  mrTabMode: 'Mode: {mode}',
  mrTabCounts: '{count} templates in total ({baseCount} baseline · {customCount} custom)',
  mrTabCustomTitle: 'Custom templates',
  mrTabAddTemplate: '+ Add template',
  mrTabPriorityHint: 'Within a hook, templates run top-down by priority; the strictest verdict wins and a block short-circuits the rest.',
  mrTabNone: 'No custom templates yet — the built-in baseline templates still review their hooks.',
  mrBaselineGroup: 'Built-in baseline templates',
  mrBaselineCount: '{count} templates',
  mrBaselineOffHint: 'Every baseline template is off: hooks without custom templates are not model-reviewed.',
  mrBaselineReadonlyHint: 'Read-only baseline prompt. To customize, copy the text into a custom template.',
  mrBaselineMetaTitle: 'Built-in baseline templates are read-only: only the enabled switch is editable, they cannot be modified or deleted. Copy into a custom template to customize.',
  mrTabDirty: 'Unsaved changes',
  mrTplNamePlaceholder: 'Template name, e.g. "Data exfiltration"',
  mrTplDelete: 'Delete template',
  mrTplOrderLabel: 'Execution order',
  mrTplOrderLine: '#{pos} of {total} in the {hook} chain',
  mrTplNoHooks: 'No hooks bound: this template never runs',
  mrTplMoveUp: 'Move up (higher priority)',
  mrTplMoveDown: 'Move down (lower priority)',
  mrTplPromptEmptyHint: 'Empty = this template is skipped entirely',
  dispositionHint: 'The strictest verdict this template may deliver: a stricter model verdict is clamped down to it (the reason is kept). "allow" makes the template audit-only.',
  dispositionObserveOnly: 'Every bound hook is observe-only: verdicts are recorded to the audit trail and never interrupt the run, so the disposition narrows to "allow / warn".',
  mrTplModalTitle: 'Template review prompt',
  metaSource: 'Source: {source}',
  metaModelVerdict: 'Model verdict: {action}',
  metaModelReason: 'Model reason',
  metaProvider: 'Review model: {name}',
  metaDuration: 'duration {ms} ms',
  labelRequest: 'Request body',
  labelResponse: 'Response body',
  labelError: 'Error',
  viewTabGuard: 'Security Review',
  tabGuardAria: 'Show the current session\u2019s security guard verdicts',
  showTabLabel: 'Show session review tab',
  showTabDesc: 'Show the current session\u2019s guard verdicts in the conversation tab strip.',

  // ── client-side validation errors (draft editor) ──
  errInArray: 'an "in" rule value must be an array',
  errValueEmpty: 'rule value cannot be empty',
  errPolicyIdEmpty: 'every policy needs a non-empty id',
  errPolicyPriority: 'policy "{id}" priority must be a number',
  errRuleFieldEmpty: 'policy "{id}" has a rule without a field',
  errPolicyNoRules: 'policy "{id}" needs at least one rule',
  errJsonShape: 'JSON must be a policies array or a {v:1, policies:[...]} table',
}

/** A copy key (keys of the canonical zh dictionary). */
export type GuardCopyKey = keyof typeof zh

/** The DSH locale service attached by the client apply (absent → browser detection). */
let localeService: { getSnapshot(): { active: string } } | undefined

/** The in-memory language preference ('auto' until the persisted value loads). */
let pref: GuardLocale = 'auto'

/**
 * Whether the conversation-view Security Review tab is shown. Written from the
 * persisted settings at boot (`loadPrefs`) and live from the settings switch;
 * `sync()` in the client apply adds/removes the `conversation.view` entry.
 */
let showTab = true

/**
 * Whether the shield button shows in the session header. Written from the
 * persisted settings at boot and live from the settings switch; the client
 * apply registers/unregisters the `conversation.session.header.utilities`
 * seat accordingly.
 */
let showHeader = true

/**
 * The guard engine master switch (mirror of the persisted `guardEnabled`
 * preference; the host engine is the authority. This value only drives the
 * settings UI checkbox). Written at boot and live from the settings switch.
 */
let guardEnabled = true

/**
 * Whether `allow` verdicts are written to the audit log (mirror of the
 * persisted `recordAllow` preference; the host audit path is the authority).
 * Written at boot and live from the settings switch.
 */
let recordAllow = false

/**
 * Rule-stage switch (mirror of the persisted `rulesEnabled` preference; the
 * host engine is the authority). Written at boot and live from the settings
 * switch. Independent of the master switch and the model stage.
 */
let rulesEnabled = true

/**
 * Model-review stage config (mirror of the persisted `modelReview`
 * preference; the host model stage is the authority). Written at boot and
 * live from the settings form; kept as a shallow-merged object so a partial
 * patch never drops sibling fields.
 */
let modelReview: ModelReviewPrefsLike = {
  enabled: false,
  mode: 'session',
  makeupReview: false,
  baseUrl: '',
  apiKey: '',
  model: '',
  timeoutMs: 12000,
  protocol: 'openai-chat',
  thinking: 'default',
}

/** Subscribers notified whenever the preference changes. */
const prefListeners = new Set<() => void>()

/**
 * Attach (or detach, with undefined) the DSH locale service. The panel mounts
 * inside the conversation header seat, so the service rides this module-level
 * holder: components keep calling the plain `t()` function, and the locale
 * subscription (installed by the client apply) re-renders the tree on
 * switches.
 */
export function attachLocale(service: { getSnapshot(): { active: string } } | undefined): void {
  localeService = service
}

/** The active DSH/browser locale id ('zh' | 'en' | …). */
function dshLocale(): string {
  return localeService?.getSnapshot().active
    ?? (typeof navigator !== 'undefined' ? navigator.language : '')
    ?? 'en'
}

/** Read the current language preference. */
export function getPreference(): GuardLocale {
  return pref
}

/** Set the in-memory preference and notify subscribers (the caller persists it). */
export function setPreference(next: GuardLocale): void {
  if (next === pref) return
  pref = next
  for (const listener of [...prefListeners]) listener()
}

/** Read the current Security Review tab visibility. */
export function getShowTab(): boolean {
  return showTab
}

/** Set the tab visibility and notify subscribers (the caller persists it). */
export function setShowTab(next: boolean): void {
  if (next === showTab) return
  showTab = next
  for (const listener of [...prefListeners]) listener()
}

/** Read the current header shield-button visibility. */
export function getShowHeader(): boolean {
  return showHeader
}

/** Set the header shield-button visibility and notify subscribers (the caller persists it). */
export function setShowHeader(next: boolean): void {
  if (next === showHeader) return
  showHeader = next
  for (const listener of [...prefListeners]) listener()
}

/** Read the mirrored guard master switch (settings UI state only). */
export function getGuardEnabled(): boolean {
  return guardEnabled
}

/** Set the mirrored guard master switch and notify subscribers (the caller persists it). */
export function setGuardEnabled(next: boolean): void {
  if (next === guardEnabled) return
  guardEnabled = next
  for (const listener of [...prefListeners]) listener()
}

/** Read the mirrored allow-recording preference (settings UI state only). */
export function getRecordAllow(): boolean {
  return recordAllow
}

/** Set the mirrored allow-recording preference and notify subscribers (the caller persists it). */
export function setRecordAllow(next: boolean): void {
  if (next === recordAllow) return
  recordAllow = next
  for (const listener of [...prefListeners]) listener()
}

/** Read the mirrored rule-stage switch (settings UI state only). */
export function getRulesEnabled(): boolean {
  return rulesEnabled
}

/** Set the mirrored rule-stage switch and notify subscribers (the caller persists it). */
export function setRulesEnabled(next: boolean): void {
  if (next === rulesEnabled) return
  rulesEnabled = next
  for (const listener of [...prefListeners]) listener()
}

/** Read the mirrored model-review config (settings UI state only). */
export function getModelReview(): ModelReviewPrefsLike {
  return modelReview
}

/** A partial model-review patch from the settings form (fields optional). */
export interface ModelReviewPatch {
  enabled?: boolean
  mode?: 'session' | 'custom'
  makeupReview?: boolean
  /** Built-in baseline template cards; only `enabled` is editable (read-only
   * name / hooks / prompt). The array replaces the stored list whole. */
  baselineTemplates?: ModelReviewPrefsLike['baselineTemplates']
  /** Custom per-hook templates; the array replaces the stored list whole. */
  templates?: ModelReviewPrefsLike['templates']
  baseUrl?: string
  apiKey?: string
  model?: string
  timeoutMs?: number
  protocol?: 'openai-chat' | 'openai-responses' | 'anthropic'
  thinking?: 'default' | 'off' | 'low' | 'medium' | 'high'
}

/** Shallow-merge a model-review patch into the mirrored config and notify
 * subscribers (the caller persists the merged result). */
export function setModelReview(patch: ModelReviewPatch): void {
  const next: ModelReviewPrefsLike = {
    ...modelReview,
    ...patch,
  }
  modelReview = next
  for (const listener of [...prefListeners]) listener()
}

/** Subscribe to preference changes; returns the disposer. */
export function subscribePreference(listener: () => void): () => void {
  prefListeners.add(listener)
  return () => { prefListeners.delete(listener) }
}

/** Subscribe to DSH-locale changes (auto mode follows it live); returns the disposer. */
export function subscribeLocale(listener: () => void): () => void {
  const service = localeService as (typeof localeService & { subscribe?: (fn: () => void) => () => void })
  if (!service || typeof service.subscribe !== 'function') return () => {}
  return service.subscribe(listener)
}

/**
 * Resolve the preference to the concrete panel language: an explicit `zh`/`en`
 * forces the language; `auto` follows the DSH active locale.
 */
export function effectiveLocale(): 'zh' | 'en' {
  if (pref === 'zh' || pref === 'en') return pref
  return dshLocale().toLowerCase().startsWith('zh') ? 'zh' : 'en'
}

/** Translate a copy key; `{name}` placeholders interpolate from `params`. */
export function t(key: GuardCopyKey, params?: Record<string, string | number>): string {
  const dict = effectiveLocale() === 'zh' ? zh : en
  let text: string = dict[key]
  if (params !== undefined) {
    for (const [name, value] of Object.entries(params)) {
      text = text.replaceAll(`{${name}}`, String(value))
    }
  }
  return text
}

/** Resolve a field-schema hint (falls back to the raw field name on miss). */
export function fieldHint(key: `hint_${string}`, fallback: string): string {
  const copy = (effectiveLocale() === 'zh' ? zh : en)[key as GuardCopyKey]
  return copy === undefined ? fallback : copy
}

/**
 * Localized copy of the built-in baseline policy messages (src/base-policies.ts).
 * Custom policies keep their authored message verbatim; only these known
 * baseline ids translate, so the audit trail's rationale reads in the panel's
 * current language instead of always-English.
 */
const BASELINE_MESSAGES: Record<string, { zh: string; en: string }> = {
  'base-block-high-risk-command': {
    zh: '高危命令被安全基线拦截（rm -rf /、管道连接 shell、无限循环、关机/格式化、shell rc 截断）',
    en: 'high-risk command blocked by security baseline (rm -rf /, pipe-to-shell, infinite loop, shutdown/format, shell rc truncation)',
  },
  'base-block-obfuscated-command': {
    zh: '混淆/编码命令投递被安全基线拦截（base64|sh、xxd -r、十六进制转义、不可见 unicode）',
    en: 'obfuscated/encoded command delivery blocked by security baseline (base64|sh, xxd -r, hex escapes, invisible unicode)',
  },
  'base-warn-overlong-command': {
    zh: '超长命令已记入审计（本身无害；仅凭长度不会单独拦截）',
    en: 'unusually long command recorded in audit (harmless by itself; length alone never blocks)',
  },
  'base-block-encoded-high-risk': {
    zh: '编码载荷解码后为高危或混淆命令（base64/hex 递归）被安全基线拦截',
    en: 'encoded payload decoding to a high-risk or obfuscated command (base64/hex recursion) blocked by security baseline',
  },
  'base-block-protected-path': {
    zh: '访问受保护路径（~/.ssh、~/.dsh、shell rc 文件、/etc 敏感文件）被安全基线拦截',
    en: 'access to protected path (~/.ssh, ~/.dsh, shell rc files, /etc sensitive files) blocked by security baseline',
  },
  'base-block-outside-delete': {
    zh: '工作区之外的删除被安全基线拦截',
    en: 'deletion outside the workspace blocked by security baseline',
  },
  'base-block-loop-hazard': {
    zh: '同一高风险变更重复超过 3 次，疑似工具循环，被安全基线拦截',
    en: 'same high-impact change repeated more than 3 times, possible tool loop, blocked by security baseline',
  },
  'base-block-artifact-execution': {
    zh: '执行本轮生成的危险脚本被安全基线拦截',
    en: 'execution of a risky script written this turn blocked by security baseline',
  },
  'base-block-exfil-chain': {
    zh: '高置信度数据外传链被安全基线拦截',
    en: 'high-confidence data exfiltration chain blocked by security baseline',
  },
  'base-warn-exfil-chain': {
    zh: '疑似数据外传链（带密钥引用或编码变换的出站），已记入审计',
    en: 'possible data exfiltration chain (outbound with secret reference or encoding transform), recorded in audit',
  },
  'base-block-tool-result-injection': {
    zh: '工具结果包含高置信度（指令/编码）提示注入（身份劫持 / 防护瘫痪 / 工具诱导 / 外传指令），被安全基线拦截',
    en: 'tool result contains a high-confidence (directive/encoded) prompt injection (persona hijack / safeguard defeat / tool luring / exfiltration instruction), blocked by security baseline',
  },
  'base-warn-tool-result-injection': {
    zh: '工具结果包含多个来源族的软注入短语，已记入审计',
    en: 'tool result contains several soft injection phrases from unrelated families, recorded in audit',
  },
  'base-block-user-intent-attack': {
    zh: '用户消息要求关闭守卫、绕过审批或忽略限制；该步骤被安全基线拒绝',
    en: 'user message requests disabling the guard, bypassing approval, or ignoring restrictions; step rejected by security baseline',
  },
  'base-warn-user-intent-attack': {
    zh: '用户消息暗示绕过限制；已由安全基线记入审计',
    en: 'user message hints at bypassing restrictions; recorded in audit by security baseline',
  },
}

/**
 * Localized copy of the built-in baseline review-template display names
 * (src/audit-prompts.ts `BASELINE_REVIEW_TEMPLATES`, mirrored by id because
 * the client bundle cannot import host-side modules). Baseline cards, chain
 * chips and the prompt viewer localize the shipped Chinese name per-interface-
 * language; custom template names render verbatim.
 */
const BASELINE_TEMPLATE_NAMES: Record<string, { zh: string; en: string }> = {
  'malicious-intent-detection': { zh: '恶意意图检测', en: 'Malicious Intent Detection' },
  'risk-instruction-detection': { zh: '风险指令检测', en: 'Risky Instruction Detection' },
  'intent-drift-detection': { zh: '意图偏离检测', en: 'Intent Drift Detection' },
}

/**
 * A review template's display name in the panel's current language. The three
 * shipped baseline template ids localize their Chinese name; anything else
 * (custom template names) renders verbatim.
 */
export function templateName(id: string, name: string): string {
  const entry = BASELINE_TEMPLATE_NAMES[id]
  return entry === undefined ? name : (entry[effectiveLocale()] ?? name)
}

/**
 * Chinese copy of the fixed English verdict scaffolding a model-stage reason
 * can embed: the two-line parser's category labels (src/model-review.ts
 * `USER_REQUEST_LINE_ACTIONS` / `AGENT_BEHAVIOR_LINE_ACTIONS` /
 * `INTENT_DRIFT_ACTIONS` — Line 1 is always English) and the JSON audit
 * parser's dimension labels (`user request [...]` / `agent behavior [...]`).
 * Mirrors the harness-side table in src/adapter.ts (the client bundle cannot
 * import host-side modules), so the approval-ask reason and the panel's
 * detail view localize identically. The free-text evidence follows the UI
 * language through the `{reason_lang}` placeholder instead.
 */
const MODEL_LABELS: ReadonlyArray<{ en: string; zh: string }> = [
  // intent-drift labels
  { en: 'Intent Drift', zh: '意图偏离' },
  { en: 'No Drift', zh: '无偏离' },
  // user-request categories
  { en: 'Instruction Override / Jailbreak Inducement', zh: '指令覆盖 / 越狱诱导' },
  { en: 'Configuration Tampering Inducement', zh: '配置篡改诱导' },
  { en: 'Role Impersonation Inducement', zh: '角色冒充诱导' },
  { en: 'Indirect Prompt Injection', zh: '间接提示注入' },
  { en: 'Tool Output Injection', zh: '工具输出注入' },
  { en: 'Conversation / Context Probing', zh: '会话 / 上下文探测' },
  { en: 'Agent Memory Extraction Inducement', zh: '智能体记忆提取诱导' },
  { en: 'Workspace Escape Inducement', zh: '工作区逃逸诱导' },
  { en: 'PII Leakage Intent', zh: 'PII 泄露意图' },
  { en: 'Confidential Business Information Leakage Intent', zh: '机密商业信息泄露意图' },
  { en: 'Cross-Tenant Data Leakage Intent', zh: '跨租户数据泄露意图' },
  { en: 'No Risk', zh: '无风险' },
  // agent-behavior categories
  { en: 'PII Leakage', zh: 'PII 泄露' },
  { en: 'Confidential Business Information Leakage', zh: '机密商业信息泄露' },
  { en: 'Cross-Tenant Data Leakage', zh: '跨租户数据泄露' },
  { en: 'Destructive Command', zh: '破坏性命令' },
  { en: 'Privilege Escalation / Permission Weakening', zh: '权限提升 / 权限弱化' },
  { en: 'Sandbox Escape Attempt', zh: '沙箱逃逸尝试' },
  { en: 'Dangerous Tool Invocation', zh: '危险工具调用' },
  { en: 'System Path Write', zh: '系统路径写入' },
  { en: 'Network Egress', zh: '网络外联' },
  { en: 'Malicious Dependency Installation', zh: '恶意依赖安装' },
  { en: 'Tool Parameter Manipulation', zh: '工具参数操纵' },
  // JSON audit dimension labels (parser emits `label [names]: evidence`)
  { en: 'user request', zh: '用户请求' },
  { en: 'agent behavior', zh: '代理行为' },
  { en: 'no risk categories detected', zh: '未检出风险类别' },
]

/** Escape a literal string for embedding in a RegExp. */
function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** Replace one verdict-label occurrence with its localized copy: the label sits
 * at a boundary (start of the reason / after a `[`/`,`/space) and is followed
 * by `:` (line-parser reason) or `,`/`]` (JSON list); case-insensitive like
 * the harness-side mirror. */
function replaceModelLabel(text: string, en: string, zh: string): string {
  const re = new RegExp(`(^|[\\[, ])(${escapeRegExp(en)})(?=[:,\\]]|$)`, 'gi')
  return text.replace(re, `$1${zh}`)
}

/**
 * A model-stage verdict reason in the panel's current language. The merged
 * reason embeds each winning template's stored name as a `[name]` prefix
 * (src/model-review.ts `mergeChainVerdicts`), so a baseline hit would leak
 * the shipped Chinese name into an English UI; known baseline names localize
 * here and custom template names stay verbatim. In a Chinese UI the fixed
 * verdict labels (`Intent Drift`, the risk categories, the JSON dimension
 * labels) also localize, matching the harness-side approval-ask reason.
 */
export function modelReason(reason: string): string {
  let text = reason
  for (const entry of Object.values(BASELINE_TEMPLATE_NAMES)) {
    const localized = entry[effectiveLocale()]
    for (const stored of [entry.zh, entry.en]) {
      if (stored !== localized) text = text.replaceAll('[' + stored + ']', '[' + localized + ']')
    }
  }
  if (effectiveLocale() === 'zh') {
    // Longest labels first: `PII Leakage Intent` must win over `PII Leakage`.
    const labels = [...MODEL_LABELS].sort((a, b) => b.en.length - a.en.length)
    for (const { en, zh } of labels) {
      text = replaceModelLabel(text, en, zh)
    }
    // JSON dimension labels appear as `label [`; the bracket forms replace the
    // `label` case-insensitively without touching evidence prose.
    text = text.replace(/user request \[/gi, '用户请求 [')
    text = text.replace(/agent behavior \[/gi, '代理行为 [')
  }
  return text
}

/**
 * Localized copy of the engine's fallback messages (src/engine.ts
 * `defaultMessage` + its allow-path notes), shown when a policy carries no
 * `message`: the deny/ask/warn fallbacks, the turn-stopping steer fallback,
 * the allow-path notes (visible when `recordAllow` is on or a stage is
 * disabled), and the model-review stage's skip/make-up notes (src/
 * model-review.ts — mirrored verbatim because the client bundle cannot import
 * host-side modules). The `policyId` is user-authored in that case, so these
 * map by the exact English string rather than by a known baseline id.
 */
const FALLBACK_MESSAGES: Record<string, { zh: string; en: string }> = {
  'blocked by security guard': {
    zh: '已被安全守卫拦截',
    en: 'blocked by security guard',
  },
  'requires approval by security guard': {
    zh: '需要用户审批',
    en: 'requires approval by security guard',
  },
  'flagged by security guard': {
    zh: '已被安全守卫标记',
    en: 'flagged by security guard',
  },
  'tool call blocked': {
    zh: '工具调用已被拦截',
    en: 'tool call blocked',
  },
  'tool call requires approval': {
    zh: '工具调用需要审批',
    en: 'tool call requires approval',
  },
  'tool result blocked': {
    zh: '工具结果已被拦截',
    en: 'tool result blocked',
  },
  'continue: blocked by security guard': {
    zh: '已被安全守卫拦截，请调整后继续',
    en: 'continue: blocked by security guard',
  },
  'no rule matched, allow by default': {
    zh: '无规则命中，默认放行',
    en: 'no rule matched, allow by default',
  },
  'guard disabled, allow by default': {
    zh: '守卫已停用，默认放行',
    en: 'guard disabled, allow by default',
  },
  'rule stage disabled, allow by default': {
    zh: '规则审查已停用，默认放行',
    en: 'rule stage disabled, allow by default',
  },
  'llm service unavailable': {
    zh: 'LLM 服务不可用',
    en: 'llm service unavailable',
  },
  'no session model route available (requestHeader has no provider/model); use the custom mode with a configured endpoint, or pick a provider/model for this session': {
    zh: '会话模型路由不可用（requestHeader 没有 provider/model）；请改用自定义模式并配置审查端点，或为本会话选择 provider/model',
    en: 'no session model route available (requestHeader has no provider/model); use the custom mode with a configured endpoint, or pick a provider/model for this session',
  },
  'session model produced no text': {
    zh: '会话模型未返回任何文本',
    en: 'session model produced no text',
  },
  'session model hit the max-tokens budget before producing text (a reasoning model may have spent it all on thinking)': {
    zh: '会话模型在产出文本前已用尽 max-tokens 预算（推理模型可能把预算全部花在了思考链上）',
    en: 'session model hit the max-tokens budget before producing text (a reasoning model may have spent it all on thinking)',
  },
  'model endpoint returned no text content': {
    zh: '模型端点未返回文本内容',
    en: 'model endpoint returned no text content',
  },
  'custom model not configured (baseUrl/model empty)': {
    zh: '自定义模型未配置（baseUrl/model 为空）',
    en: 'custom model not configured (baseUrl/model empty)',
  },
  'model output not parseable': {
    zh: '模型输出无法解析',
    en: 'model output not parseable',
  },
  'session model route not yet available: the harness appends the request header (with provider/model) to the session log only when it dispatches the first request, so the first guarded event of a session races it. Decision fell through to the rules stage and the event was queued for a post-hoc make-up review': {
    zh: '会话模型路由尚未就绪：harness 只有在派发会话第一次请求时，才会把请求头（含 provider/model）写入会话日志，因此会话的第一个守卫事件与它存在时序竞争。判决按规则阶段放行，该事件已入队等待事后补审',
    en: 'session model route not yet available: the harness appends the request header (with provider/model) to the session log only when it dispatches the first request, so the first guarded event of a session races it. Decision fell through to the rules stage and the event was queued for a post-hoc make-up review',
  },
  'post-hoc make-up review of an event skipped on first-request timing; audit-only — this verdict did NOT affect the already-delivered decision': {
    zh: '对因首次请求时序竞争而被跳过的事件的事后补审；仅留痕——该判决不影响当时已交付的决策',
    en: 'post-hoc make-up review of an event skipped on first-request timing; audit-only — this verdict did NOT affect the already-delivered decision',
  },
}

/**
 * Prefix-localized messages whose tail is dynamic (an error/status detail):
 * the engine-error message and the model-review endpoint/stream failures.
 * The prefix is translated and the original detail tail kept verbatim so the
 * diagnostic value survives localization.
 */
const PREFIX_MESSAGES: ReadonlyArray<{ prefix: string; zh: string }> = [
  { prefix: 'guard engine error, allow by default: ', zh: '守卫引擎错误，默认放行：' },
  { prefix: 'guard engine error, block by default: ', zh: '守卫引擎错误，默认拦截：' },
  { prefix: 'model endpoint responded ', zh: '模型端点响应 ' },
  { prefix: 'session model stream error: ', zh: '会话模型流式调用失败：' },
  { prefix: 'session model stream aborted: ', zh: '会话模型流式调用中止：' },
  { prefix: 'session model review aborted by the timeout deadline: ', zh: '模型审查因超时时限被中止：' },
]

/**
 * A verdict row's rationale in the panel's current language. Built-in baseline
 * messages and engine fallback strings localize per-interface-language;
 * anything else (custom policy messages) renders verbatim.
 */
export function verdictMessage(row: { policyId?: string; message?: string }): string {
  const message = row.message
  if (message === undefined || message === '') return ''
  const id = row.policyId
  if (id !== undefined && Object.prototype.hasOwnProperty.call(BASELINE_MESSAGES, id)) {
    return BASELINE_MESSAGES[id]?.[effectiveLocale()] ?? message
  }
  if (Object.prototype.hasOwnProperty.call(FALLBACK_MESSAGES, message)) {
    return FALLBACK_MESSAGES[message]?.[effectiveLocale()] ?? message
  }
  if (effectiveLocale() === 'zh') {
    for (const { prefix, zh } of PREFIX_MESSAGES) {
      if (message.startsWith(prefix)) return zh + message.slice(prefix.length)
    }
  }
  return message
}