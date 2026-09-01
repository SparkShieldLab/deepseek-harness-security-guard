/**
 * Client-bundle contract + render smoke tests.
 *
 * The real panel renders inside the harness browser, which this repo cannot
 * boot. What it CAN do is load the built bundle (lib/client.js) in a vm with
 * a minimal module-loader stub + React stub and:
 *
 *   - assert the module-loader contract (id, factory shape, exports.apply /
 *     exports.inject);
 *   - evaluate the factory with a stubbed `require` and walk the element
 *     tree the panel builds — catching runtime errors (undefined
 *     identifiers, broken component logic, bad prop wiring) that a
 *     parse-only check misses.
 *
 * No DOM, no network: `fetch` is stubbed to answer the /guard routes with
 * empty payloads; effects are collected but only run where the test needs
 * them. `injectStyle` runs against a minimal document stub.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import vm from 'node:vm'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const BUNDLE = readFileSync(join(ROOT, 'lib/client.js'), 'utf8')

/** Minimal React: createElement descriptors + index-based hook storage. */
function makeRuntime() {
  const states = []
  const setters = []
  const effects = []
  let cursor = 0
  let overrides = {}

  const React = {
    createElement(type, props) {
      const children = []
      for (let k = 2; k < arguments.length; k++) children.push(arguments[k])
      // Real React folds element children into props.children; function
      // components (e.g. SettingsGroup) rely on that injection.
      const allProps = props || {}
      if (children.length > 0) allProps.children = children.length === 1 ? children[0] : children
      return { type, props: allProps, children }
    },
    useState(initial) {
      const idx = cursor++
      if (states[idx] === undefined) {
        states[idx] = {
          value: Object.prototype.hasOwnProperty.call(overrides, idx)
            ? overrides[idx]
            : (typeof initial === 'function' ? initial() : initial),
        }
      }
      const set = (v) => { states[idx].value = typeof v === 'function' ? v(states[idx].value) : v }
      setters[idx] = set
      return [states[idx].value, set]
    },
    useReducer(reducer, initial) {
      const idx = cursor++
      if (states[idx] === undefined) states[idx] = { value: initial }
      const set = (v) => { states[idx].value = reducer(states[idx].value, v) }
      setters[idx] = set
      return [states[idx].value, set]
    },
    useCallback(fn) { return fn },
    useEffect(fn) { effects.push(fn) },
    useRef(initial) {
      const idx = cursor++
      if (states[idx] === undefined) states[idx] = { value: { current: initial } }
      return states[idx].value
    },
  }

  return {
    React,
    fetch: async () => ({ ok: true, json: async () => [] }),
    beginPass() { cursor = 0; overrides = {} },
    setOverride(idx, value) { overrides[idx] = value },
    setter(idx) { return setters[idx] },
    get states() { return states },
    effects,
  }
}

/**
 * Load lib/client.js in a vm, capture the registered module-loader factory,
 * then materialize it with the stubbed require. Returns { apply, inject }.
 */
function loadBundle(runtime) {
  const events = {}
  const captured = { css: '' }
  const sandbox = {
    window: {
      __ModuleLoader__: {
        load(entry) {
          if (typeof entry !== 'object' || typeof entry.factory !== 'function') {
            throw new Error('bad loader entry')
          }
          sandbox.__capturedFactory = entry.factory
        },
      },
      confirm: () => true,
    },
    // Minimal document for injectStyle (querySelector/createElement/head);
    // addEventListener/removeEventListener record handlers so tests can drive
    // document-level close-on-outside-click behavior. The textContent setter
    // also captures the injected stylesheet so CSS-only contracts (the editor
    // dialog's definite height, the read-only preview look) can be asserted.
    document: {
      querySelector() { return null },
      createElement() { return { dataset: {}, set textContent(v) { captured.css = String(v) } } },
      head: { appendChild() {} },
      addEventListener(type, fn) { (events[type] || (events[type] = [])).push(fn) },
      removeEventListener(type, fn) {
        const list = events[type]
        if (list) {
          const i = list.indexOf(fn)
          if (i !== -1) list.splice(i, 1)
        }
      },
    },
    fetch: runtime.fetch,
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    Date,
    JSON,
    Symbol,
    Math,
  }
  vm.createContext(sandbox)
  new vm.Script(BUNDLE, { filename: 'lib/client.js' }).runInContext(sandbox)
  assert.ok(typeof sandbox.__capturedFactory === 'function', 'module loader factory not registered')
  const exportsObj = sandbox.__capturedFactory((spec) => {
    if (spec === 'react' || spec === 'react/jsx-runtime') return runtime.React
    throw new Error(`unexpected require in bundle: ${spec}`)
  })
  // Expose the captured document event handlers for tests to simulate.
  exportsObj.events = events
  // Expose the sandbox window so a test can drive native dialogs (the bundle
  // asks `window.confirm` before overwriting a custom review prompt) and count
  // how often the prompt came up.
  exportsObj.sandboxWindow = sandbox.window
  // Expose the injected stylesheet text (empty until apply() runs injectStyle).
  exportsObj.css = () => captured.css
  return exportsObj
}

/** Recursively invoke function components / collect plain element children. */
function walk(node) {
  if (node === null || node === undefined || typeof node === 'boolean') return
  if (Array.isArray(node)) { for (const n of node) walk(n); return }
  if (typeof node === 'string' || typeof node === 'number') return
  const { type, props, children } = node
  if (typeof type === 'function') {
    walk(type(props))
  } else {
    for (const c of children) walk(c)
  }
}

/** Mount the bundle: run apply() with a stub ctx and return the registered component. */
function mount(exportsObj, runtime) {
  const seats = {}
  let registeredComponent = null
  exportsObj.apply({
    slots: {
      inject(name, factory) { seats[name] = factory },
      register(spec, component) { registeredComponent = component; return component },
    },
    // Run the boot effects (prefs load, locale report) when a runtime is
    // supplied so the module store picks up seeded prefs; bare `mount()`
    // (settings/header tests that need no prefs) keeps them inert.
    effect(fn) { if (runtime) runtime.effects.push(fn) },
  })
  assert.ok(seats['conversation.session.header.utilities'], 'session-header utility seat not registered')
  // The header seat factory is now preference-driven: it registers the
  // component through ctx.slots.register and returns the disposer iterable.
  // Run the factory so the register mock captures the GuardPanel component to
  // walk.
  seats['conversation.session.header.utilities']()
  assert.ok(registeredComponent, 'header seat component was not registered')
  return registeredComponent
}

/** A representative policy table as the form renders it (draft shape). */
function sampleDraft() {
  return [{
    key: 1,
    id: 'p1',
    enabled: true,
    priority: '100',
    action: 'block',
    mode: '',
    message: 'block bash',
    hooks: ['tools/pre-execute'],
    rules: [
      { key: 11, field: 'toolName', operator: 'in', valueText: 'bash, sh' },
      { key: 12, field: 'highRisk', operator: 'eq', valueText: 'true' },
      { key: 13, field: 'command', operator: 'matches', valueText: 'rm -rf /*' },
    ],
    open: true,
  }, {
    key: 2,
    id: 'p2',
    enabled: true,
    priority: '50',
    action: 'warn',
    mode: 'monitor',
    message: '',
    hooks: ['agent/pre-step'],
    rules: [{ key: 21, field: 'userIntentRisk', operator: 'eq', valueText: 'warn' }],
    open: false,
  }]
}

test('bundle: registers under the package name with a factory and exports apply/inject', () => {
  const runtime = makeRuntime()
  const exportsObj = loadBundle(runtime)
  assert.equal(typeof exportsObj.apply, 'function')
  assert.deepEqual(Array.from(exportsObj.inject), ['slots', 'locale'])
})

test('bundle: registered slot entry carries no plain-object inject (renderer runInject contract)', () => {
  const runtime = makeRuntime()
  const seats = {}
  const specs = []
  const exportsObj = loadBundle(runtime)
  exportsObj.apply({
    slots: {
      inject(name, factory) { seats[name] = factory; factory() },
      register(spec, component) { specs.push(spec) },
    },
    effect() {},
  })
  const spec = specs.find((s) => s.name === 'conversation.session.header.utilities')
  assert.ok(spec, 'header utility seat spec missing')
  // The slot renderer calls entry.inject as a thunk (runInject: inject(...args));
  // a plain object would throw `inject is not a function`, be caught by the
  // SlotErrorBoundary and silently abdicate the entry — no button, no error.
  assert.equal(spec.inject, undefined, 'slot entry must not carry a plain-object inject')
})

test('bundle: header mount renders the Verdict Log tree without errors', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  runtime.beginPass()
  walk({ type: GuardPanel, props: {} })
  // open + verdict effects were scheduled (poll + open-refresh paths exist)
  assert.ok(runtime.effects.length >= 2, 'expected poll/refresh effects to be registered')
})

/** Collect every element node matching `pred` (className or children checks). */
function collect(node, pred, out = []) {
  if (node === null || node === undefined || typeof node !== 'object') return out
  if (Array.isArray(node)) { for (const n of node) collect(n, pred, out); return out }
  const { type, props, children } = node
  if (typeof type === 'function') {
    collect(type(props), pred, out)
  } else {
    if (pred(node)) out.push(node)
    for (const c of children) collect(c, pred, out)
  }
  return out
}

test('bundle: the panel shell is ONE uniform width across all tabs (no per-tab resize)', () => {
  const runtime = makeRuntime()
  const exportsObj = loadBundle(runtime)
  const GuardPanel = mount(exportsObj)
  const tree = { type: GuardPanel, props: {} }
  // `tab` is the FIRST useState in GuardPanel (hook slot 0 — useGuardStore
  // runs after it). beginPass() resets cursor AND clears overrides, so the
  // override must be set after beginPass. Note: `collect` also renders
  // function components, so every collect() is its own pass.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  const hdrBtn = closed[0]
  assert.ok(hdrBtn && typeof hdrBtn.props.onClick === 'function', 'shield toggle button present')
  hdrBtn.props.onClick()
  runtime.beginPass()
  runtime.setter(2)(sampleDraft())
  const opened = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-panel'))
  assert.equal(opened.length, 1, 'exactly one .dsg-panel shell')
  const outer = opened[0]
  assert.equal(outer.props.className, 'dsg-panel',
    'the shell carries no per-tab width class (same width on every tab)')

  // The uniform width lives in the stylesheet itself: .dsg-panel IS the
  // 560px shell, and the per-tab wide variant is gone for good.
  const css = exportsObj.css()
  const panelRule = /\.dsg-panel\{[^}]*\}/.exec(css)?.[0] ?? ''
  assert.ok(panelRule.includes('width:min(560px,calc(100vw - 24px))'),
    `.dsg-panel itself must be the 560px shell (got: ${panelRule})`)
  assert.ok(!/\.dsg-panel-wide\{/.test(css), 'no .dsg-panel-wide rule may remain (per-tab resize)')

  // The content container directly inside .dsg-body must NOT carry the shell
  // class (and with it the fixed width).
  const body = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-body'))[0]
  assert.ok(body, '.dsg-body exists')
  const directChildren = body.children.flat().filter((c) => c && typeof c === 'object' && c.type)
  const container = directChildren[0]
  const cls = String(container.props?.className || '')
  assert.ok(!cls.split(' ').includes('dsg-panel'),
    `content container must not be width-constrained (got className: ${JSON.stringify(cls)})`)
})

test('bundle: save/reload live in a pinned dsg-footer, outside the scrollable dsg-body', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  runtime.setter(2)(sampleDraft())

  const footer = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-footer'))[0]
  assert.ok(footer, '.dsg-footer exists on the config tab')
  assert.ok(footer !== collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-body'))[0],
    '.dsg-footer must be a sibling of .dsg-body, not inside it')

  // Save + Reload buttons are descendants of the footer, not of the scroll area.
  const insideFooter = (label) => {
    const found = []
    const walk = (n) => {
      if (!n || typeof n !== 'object') return
      if (Array.isArray(n)) return n.forEach(walk)
      if (n.children) n.children.forEach(walk)
      if (typeof n.type === 'string' && n.type === 'button' && n.children.some((c) => c === label)) found.push(n)
    }
    walk(footer)
    return found
  }
  assert.equal(insideFooter('Save').length, 1, 'Save button sits in the footer')
  assert.equal(insideFooter('Reload').length, 1, 'Reload button sits in the footer')

  // The model-review tab pins its own footer twin (Save/Reload + the draft
  // banner), also a sibling of the scrollable body.
  runtime.beginPass()
  runtime.setOverride(0, 'model')
  const modelFooter = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-footer'))[0]
  assert.ok(modelFooter, '.dsg-footer exists on the model tab too')
  assert.ok(modelFooter !== collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-body'))[0],
    'the model footer is a sibling of .dsg-body, not inside it')
  assert.deepEqual(collect(modelFooter, (n) => n && n.type === 'button').map((n) => n.children.join('')),
    ['Save', 'Reload'], 'the model footer carries Save + Reload')
})

test('bundle: Rule Config tab renders policy cards, rule rows and JSON view without errors', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))

  // First pass: force the config tab (hook slot 0 — tab is GuardPanel's first
  // useState). beginPass() clears overrides, so set the override after it.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  walk({ type: GuardPanel, props: {} })

  // Second pass: inject a populated draft (state index 2) and re-render,
  // exercising PolicyEditor (expanded + collapsed), RuleRow (in/eq/matches,
  // boolean-field select) and the empty-policy banner logic.
  runtime.setter(2)(sampleDraft())
  runtime.beginPass()
  walk({ type: GuardPanel, props: {} })

  // Third pass: empty draft on the config tab → banner + "no policies" note.
  runtime.setter(2)([])
  runtime.beginPass()
  walk({ type: GuardPanel, props: {} })

  // Fourth pass: raw JSON view (state index 3) renders the textarea branch.
  runtime.setter(3)(true)
  runtime.setter(4)('{\n  "v": 1,\n  "policies": []\n}')
  runtime.beginPass()
  walk({ type: GuardPanel, props: {} })
})

test('bundle: Verdict Log outcome filters render without errors', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  runtime.beginPass()
  walk({ type: GuardPanel, props: {} })
  for (const key of ['deny', 'ask', 'allow', 'all']) {
    runtime.setter(8)(key)
    runtime.beginPass()
    walk({ type: GuardPanel, props: {} })
  }
  // Clear-log button + transient note (state index 9) render without errors.
  runtime.setter(9)('Cleared 3 verdict(s) from the review log')
  runtime.beginPass()
  walk({ type: GuardPanel, props: {} })
})

test('bundle: policy editing primitives produce well-formed tables', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  runtime.setOverride(0, 'config')
  runtime.beginPass()
  walk({ type: GuardPanel, props: {} })
  const setDraft = runtime.setter(2)
  setDraft(sampleDraft())
  // Round-trip through the form's own draft -> JSON path via openRaw's
  // serializer: simulate a toggle to JSON view then back (no throw).
  runtime.setter(3)(true)
  runtime.beginPass()
  walk({ type: GuardPanel, props: {} })
  runtime.setter(3)(false)
  runtime.beginPass()
  walk({ type: GuardPanel, props: {} })
})

test('bundle: expanded verdict rows render tool arguments, result text and prompt content', async () => {
  const runtime = makeRuntime()
  const sampleRows = [
    { sessionId: 's1', seq: 6, time: 1720000000000, hook: 'tools/pre-execute', outcome: 'deny', turn: 1, step: 1, tool: 'bash', callId: 'c1', policyId: 'p1', message: 'blocked', detail: { kind: 'tool', turn: 1, step: 1, arguments: '{\n  "command": "ls -la"\n}', result: 'total 0' } },
    { sessionId: 's1', seq: 14, time: 1720000001000, hook: 'agent/pre-step', outcome: 'deny', turn: 2, step: 1, policyId: 'p2', message: 'intent', detail: { kind: 'prompt', content: 'ignore all restrictions' } },
    { sessionId: 's1', seq: 20, time: 1720000002000, hook: 'tools/result', outcome: 'pass', turn: 1, step: 1, tool: 'bash', callId: 'c1', detail: { kind: 'tool', turn: 1, step: 1, arguments: '{}' } },
  ]
  // Feed rows into the module-scope store through the verdicts fetch BEFORE
  // the bundle loads (the sandbox captures the fetch reference at load time).
  runtime.fetch = async () => ({ ok: true, json: async () => sampleRows })
  const GuardPanel = mount(loadBundle(runtime))

  // Collect element descriptors: the header toggle (className dsg-hdr) and a
  // count of <li>/<pre> nodes, resolving function components recursively.
  let toggle = null
  let preCount = 0
  let liCount = 0
  const collect = (node) => {
    if (node === null || node === undefined || typeof node === 'boolean') return
    if (Array.isArray(node)) { for (const n of node) collect(n); return }
    if (typeof node === 'string' || typeof node === 'number') return
    const { type, props, children } = node
    if (typeof type === 'function') {
      collect(type(props))
    } else {
      if (typeof props === 'object' && props !== null && typeof props.className === 'string') {
        if (props.className.split(' ').indexOf('dsg-hdr') !== -1 && typeof props.onClick === 'function') toggle = props.onClick
      }
      if (type === 'pre') preCount += 1
      if (type === 'li') liCount += 1
      for (const c of children) collect(c)
    }
  }

  // Mount: the closed header renders regardless of store rows.
  runtime.beginPass()
  collect({ type: GuardPanel, props: {} })
  assert.ok(typeof toggle === 'function', 'header toggle not found')

  // Run the refresh effects so the module store picks up the sample rows
  // (the silent refresh path), then open through the header toggle.
  for (const fn of runtime.effects.slice()) { fn() }
  await new Promise((resolve) => setTimeout(resolve, 20))
  toggle()
  runtime.beginPass()
  collect({ type: GuardPanel, props: {} })

  // Expand every row (state index 10) and re-render the detail bodies.
  runtime.setter(10)({ 's1:6': true, 's1:14': true, 's1:20': true })
  runtime.beginPass()
  preCount = 0
  liCount = 0
  collect({ type: GuardPanel, props: {} })
  assert.ok(liCount >= 3, 'expected verdict rows, got ' + liCount)
  // 2 tool rows each render an Arguments pre, 1 tool row renders a Result pre, 1 prompt row renders a Prompt pre
  assert.ok(preCount >= 4, 'expected detail pre blocks, got ' + preCount)
})

test('bundle: ask verdict rows render the approval outcome badge', async () => {
  const runtime = makeRuntime()
  const sampleRows = [
    { sessionId: 's1', seq: 6, time: 1720000000000, hook: 'tools/pre-execute', outcome: 'ask', turn: 1, step: 1, tool: 'bash', callId: 'c1', action: 'ask', approval: 'rejected', message: 'needs approval', detail: { kind: 'tool', turn: 1, step: 1, arguments: '{}' } },
  ]
  runtime.fetch = async () => ({ ok: true, json: async () => sampleRows })
  const GuardPanel = mount(loadBundle(runtime))

  const collectText = (node, out = []) => {
    if (node == null || typeof node === 'boolean') return out
    if (Array.isArray(node)) { for (const n of node) collectText(n, out); return out }
    if (typeof node === 'string' || typeof node === 'number') { out.push(String(node)); return out }
    const { type, props, children } = node
    if (typeof type === 'function') { collectText(type(props), out) } else { collectText(children, out) }
    return out
  }
  const texts = () => {
    runtime.beginPass()
    return collectText({ type: GuardPanel, props: {} })
  }
  // Before the fetch resolves, the store is empty — no badge yet.
  assert.ok(!texts().includes('Rejected'), 'no badge before data arrives')

  // Resolve the refresh fetch, then open the panel to render the verdict list.
  for (const fn of runtime.effects.slice()) { fn() }
  await new Promise((resolve) => setTimeout(resolve, 20))
  let toggle = null
  const findToggle = (node) => {
    if (node == null || typeof node === 'boolean') return
    if (Array.isArray(node)) return node.forEach(findToggle)
    if (typeof node === 'object' && typeof node.type === 'function') return findToggle(node.type(node.props))
    if (String(node.props?.className || '').split(' ').includes('dsg-hdr') && typeof node.props.onClick === 'function') toggle = node.props.onClick
    if (Array.isArray(node.children)) node.children.forEach(findToggle)
  }
  runtime.beginPass()
  findToggle({ type: GuardPanel, props: {} })
  assert.ok(typeof toggle === 'function', 'header toggle found')
  toggle()
  const rendered = texts()
  assert.ok(rendered.includes('Rejected'), 'approval outcome badge rendered for the rejected ask verdict')
})

test('bundle: document pointerdown outside the shield button + panel closes the open panel', () => {
  const runtime = makeRuntime()
  const exportsObj = loadBundle(runtime)
  const GuardPanel = mount(exportsObj)
  const tree = { type: GuardPanel, props: {} }

  const count = (cls) => collect(tree, (n) => String(n.props?.className || '').split(' ').includes(cls)).length

  // Open the panel through the header toggle.
  runtime.beginPass()
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  assert.ok(closed[0], 'header toggle not found')
  closed[0].props.onClick()

  runtime.beginPass()
  assert.equal(count('dsg-panel'), 1, 'panel open after header toggle')

  // Run effects (in push order) until the outside-click handler registers on
  // the stub document. Stopping early avoids the open-state poll effect, whose
  // real setInterval would keep the test process alive.
  for (const fn of runtime.effects.slice()) {
    fn()
    if ((exportsObj.events.pointerdown || []).length >= 1) break
  }
  const handlers = exportsObj.events.pointerdown || []
  assert.ok(handlers.length >= 1, 'a document pointerdown handler is registered while the panel is open')

  // A click inside the shield root (button or panel) must NOT close the panel.
  for (const h of handlers) h({ target: { closest: () => ({ className: 'dsg-root' }) } })
  runtime.beginPass()
  assert.equal(count('dsg-panel'), 1, 'panel stays open when clicking inside the menu')

  // A click anywhere else closes the panel.
  for (const h of handlers) h({ target: { closest: () => null } })
  runtime.beginPass()
  assert.equal(count('dsg-panel'), 0, 'panel auto-hides when clicking outside the menu')
})

test('bundle: rule row controls follow the field type (dropdown + operator trim)', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setter(2)([
    {
      key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '',
      message: '', hooks: ['tools/pre-execute'], open: true,
      rules: [
        { key: 11, field: 'highRisk', operator: 'eq', valueText: 'true' },
        { key: 12, field: 'toolName', operator: 'in', valueText: 'bash' },
        { key: 13, field: 'toolName', operator: 'in', valueText: 'bash, sh' },
        { key: 14, field: 'content', operator: 'contains', valueText: 'BEGIN PRIVATE KEY' },
      ],
    },
  ])
  const rules = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-rule'))
  assert.equal(rules.length, 4, 'four rule rows')

  // children of .dsg-rule: [fieldControl, operatorSelect, valueControl, btn]
  const flatKids = (n) => (n.children || []).filter(Boolean).flat()
  const opOptions = (n) => flatKids(flatKids(n)[1]).map((o) => o.props.value)

  // 1. boolean field: value dropdown + operator trimmed to eq/neq
  const r1 = flatKids(rules[0])
  assert.equal(r1[0].type, 'div', 'known field wraps in .dsg-fcell')
  assert.equal(r1[0].children[0].type, 'select', 'known field renders as a dropdown inside the cell')
  assert.equal(r1[2].type, 'select', 'boolean value renders as a dropdown')
  assert.deepEqual(opOptions(rules[0]), ['eq', 'neq'], 'boolean operator trimmed to eq/neq')

  // 2. enum field with a candidate value: value renders as a dropdown
  const r2 = flatKids(rules[1])
  assert.equal(r2[2].type, 'select', 'enum candidate value renders as a dropdown')
  assert.deepEqual(opOptions(rules[1]), ['eq', 'neq', 'in', 'matches', 'regex'], 'enum operator trimmed to eq/neq/in/matches/regex')

  // 3. enum field with a custom value (not in candidates): value stays an input
  const r3 = flatKids(rules[2])
  assert.equal(r3[2].type, 'input', 'enum custom value renders as free-form input')

  // 4. text field: free-form input + full operator set
  const r4 = flatKids(rules[3])
  assert.equal(r4[2].type, 'input', 'text value stays free-form')
  assert.deepEqual(opOptions(rules[3]), ['eq', 'neq', 'contains', 'in', 'matches', 'regex'], 'text operator keeps the full set')

  // field dropdown carries a custom entry + groups fields under optgroups so
  // the hook-surface classification is visible; the help button sits beside it.
  const fcell = flatKids(rules[0])[0]
  const fieldSelect = fcell.children[0]
  const fieldValues = (() => {
    const out = []
    const walk = (n) => {
      if (n && n.props && typeof n.props.value === 'string' && n.props.value) out.push(n.props.value)
      if (Array.isArray(n)) return n.forEach(walk)
      if (n && n.children) n.children.forEach((c) => walk(c))
    }
    walk(fieldSelect)
    return out
  })()
  assert.ok(fieldValues.includes('__custom__'), 'field dropdown offers a custom entry')
  assert.ok(fieldValues.includes('toolName'), 'field dropdown lists known fields')
  const groups = (() => {
    const out = []
    const walk = (n) => {
      if (n && n.type === 'optgroup') out.push(n)
      if (Array.isArray(n)) return n.forEach(walk)
      if (n && n.children) n.children.forEach((c) => walk(c))
    }
    walk(fieldSelect)
    return out
  })()
  assert.ok(groups.length >= 2, 'fields grouped under optgroup headers')
  assert.deepEqual(groups.map((g) => g.props.label),
    ['Universal', 'Tool call'], 'single-hook scope shows only the matching surface groups')
  const help = (fcell.children || []).filter((c) => c && c.props && c.props.className === 'dsg-help')[0]
  assert.ok(help && help.props['data-hint'], 'help button carries a description')
})

test('bundle: policy delete survives the onClick event argument (regression: event used as key)', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setter(2)([
    { key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '', message: '', hooks: ['tools/pre-execute'], open: false, rules: [{ key: 11, field: 'highRisk', operator: 'eq', valueText: 'true' }] },
    { key: 2, id: 'p2', enabled: true, priority: '100', action: 'block', mode: '', message: '', hooks: ['tools/pre-execute'], open: false, rules: [{ key: 21, field: 'toolName', operator: 'eq', valueText: 'bash' }] },
  ])
  let cards = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-pcard'))
  assert.equal(cards.length, 2, 'two policy cards')

  // React calls onClick(event) — find the Delete policy button and invoke it
  // with a fake MouseEvent-like object as React would. Every collect() is its
  // own pass, so beginPass() again before rendering.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const deleteBtn = collect(tree, (n) => String(n.props?.title || '') === 'Delete policy')[0]
  assert.ok(deleteBtn, 'delete-policy button present')
  deleteBtn.props.onClick({ stopPropagation() {}, type: 'click' })

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  cards = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-pcard'))
  assert.equal(cards.length, 1, 'policy deleted after confirm (event object must not leak into the key)')
  const ids = cards.map((c) => {
    const idInput = c.children[0].children.filter(Boolean).find((x) => x && String(x.props?.className || '').includes('dsg-input'))
    return String(idInput.props.value)
  })
  assert.ok(ids.includes('p2') && !ids.includes('p1'), 'p1 removed, p2 kept')
})

test('bundle: config tab groups baseline vs custom policies (badge + baseline group)', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setter(2)([
    { key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '', message: '', hooks: ['tools/pre-execute'], open: true, rules: [{ key: 11, field: 'highRisk', operator: 'eq', valueText: 'true' }] },
    { key: 2, id: 'base-block-high-risk-command', enabled: true, priority: '50', action: 'block', mode: '', message: '', hooks: ['tools/pre-execute'], open: true, rules: [{ key: 21, field: 'highRisk', operator: 'eq', valueText: 'true' }] },
  ])

  // Custom card renders with CUSTOM badge and no baseline shell class.
  const customBadge = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-badge-custom'))
  assert.equal(customBadge.length, 1, 'custom badge rendered')
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  // The baseline group + its cards are EXPANDED by default now, so the
  // BASELINE badge and the baseline card body show immediately.
  const baseBadge = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-badge-base'))
  assert.equal(baseBadge.length, 1, 'baseline badge rendered (baseline group expanded by default)')

  // Group title present with count + toggle.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const title = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-group-title'))[0]
  assert.ok(title, 'baseline group title present')
  const collectText = (n) => {
    if (n == null) return ''
    if (typeof n === 'string') return n
    if (typeof n === 'object' && Array.isArray(n)) return n.map(collectText).join('')
    const kids = n.children
    return Array.isArray(kids) ? kids.map(collectText).join('') : collectText(kids)
  }
  const titleText = collectText(title)
  assert.ok(titleText.includes('1 policies'), 'baseline group shows count: ' + titleText)

  // Baseline card rendered with the group open.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  let baseCards = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-pcard-base'))
  assert.equal(baseCards.length, 1, 'baseline cards shown (group starts expanded)')

  // Collapsing the group hides the baseline card.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const toggle = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-group-toggle'))[0]
  toggle.props.onClick()
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  baseCards = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-pcard-base'))
  assert.equal(baseCards.length, 0, 'collapsing the baseline group hides the baseline card')
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const baseBadges = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-badge-base'))
  assert.equal(baseBadges.length, 0, 'no BASELINE badge while the group is collapsed')
})

test('bundle: baseline policy is read-only (no delete button, read-only hint + locked controls), custom keeps delete', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setter(2)([
    { key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '', message: '', hooks: ['tools/pre-execute'], open: true, rules: [{ key: 11, field: 'highRisk', operator: 'eq', valueText: 'true' }] },
    { key: 2, id: 'base-block-high-risk-command', enabled: true, priority: '50', action: 'block', mode: '', message: '', hooks: ['tools/pre-execute'], open: true, rules: [{ key: 21, field: 'highRisk', operator: 'eq', valueText: 'true' }] },
  ])

  // The baseline group is EXPANDED by default, so both cards render already.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const deleteBtns = collect(tree, (n) => n.props?.title === 'Delete policy')
  assert.equal(deleteBtns.length, 1, 'only the custom policy has a delete button')

  // The baseline card head must carry the read-only hint instead.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const baseCard = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-pcard-base'))[0]
  assert.ok(baseCard, 'baseline card rendered')
  const headKids = baseCard.children[0].children.filter(Boolean)
  const hint = headKids.find((c) => c && String(c.props?.title || '').includes('read-only'))
  assert.ok(hint, 'baseline card shows read-only hint')
  assert.equal(headKids.some((c) => c && c.props?.title === 'Delete policy'), false, 'baseline card has no delete button')

  // The baseline card is display-only: id input read-only, action select
  // disabled — only the enabled checkbox stays editable.
  const idInput = headKids.find((c) => c && c.type === 'input' && String(c.props?.className || '').includes('dsg-input'))
  assert.ok(idInput, 'baseline id input rendered')
  assert.equal(idInput.props.readOnly, true, 'baseline id input is read-only')
  const actionSelect = headKids.find((c) => c && c.type === 'select')
  assert.ok(actionSelect, 'baseline action select rendered')
  assert.equal(actionSelect.props.disabled, true, 'baseline action select is disabled')
  // Rule rows inside the baseline body are inert too (field select disabled).
  const bodySelects = collect(baseCard, (n) => n && n.type === 'select' && n !== actionSelect)
  assert.ok(bodySelects.length > 0, 'baseline body renders selects (action dropdowns of rule rows)')
  for (const s of bodySelects) assert.equal(s.props.disabled, true, 'baseline rule select is disabled')

  // Custom card still has its delete button wired to onDelete.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const customCard = collect(tree, (n) => {
    const kids = (n && n.children && n.children[0] && n.children[0].children) || []
    return kids.some((c) => c && c.props && c.props.title === 'Delete policy')
  })[0]
  assert.ok(customCard, 'custom card found')
  const delBtn = customCard.children[0].children.filter(Boolean).find((c) => c && c.props?.title === 'Delete policy')
  assert.equal(typeof delBtn.props.onClick, 'function', 'custom delete button wired')
})

test('bundle: + Add Policy inserts the new policy at the top of the list', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setter(2)([
    { key: 1, id: 'existing', enabled: true, priority: '100', action: 'block', mode: '', message: '', hooks: ['tools/pre-execute'], open: true, rules: [{ key: 11, field: 'highRisk', operator: 'eq', valueText: 'true' }] },
  ])

  // Click "+ Add Policy".
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const addBtn = collect(tree, (n) => n && n.children && n.children[0] === '+ Add Policy')[0]
  addBtn.props.onClick()

  // New policy (auto id) must be the FIRST card in the list, before 'existing'.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const cards = collect(tree, (n) => n && n.props && typeof n.props.className === 'string' && n.props.className.split(' ').includes('dsg-pcard'))
  const ids = cards.map((c) => {
    const idInput = c.children[0].children.filter(Boolean).find((x) => x && String(x.props?.className || '').includes('dsg-input'))
    return String(idInput ? idInput.props.value : 'MISSING')
  })
  assert.equal(ids.length, 2, 'two policy cards rendered')
  assert.equal(ids[0], '', 'new policy (empty auto id) first, got: ' + JSON.stringify(ids))
  assert.equal(ids[1], 'existing', 'existing policy stays second, got: ' + JSON.stringify(ids))
})

test('bundle: command rule row offers matches operator for glob wildcards (ls*)', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setter(2)([
    {
      key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '',
      message: '', hooks: ['tools/pre-execute'], open: true,
      rules: [{ key: 11, field: 'command', operator: 'matches', valueText: 'ls*' }],
    },
  ])
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const rules = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-rule'))
  assert.equal(rules.length, 1, 'one rule row')
  const flatKids = (n) => (n.children || []).filter(Boolean).flat()
  const opOptions = (n) => flatKids(flatKids(n)[1]).map((o) => o.props.value)
  assert.deepEqual(opOptions(rules[0]), ['eq', 'neq', 'in', 'matches', 'regex'], 'command offers matches/regex for glob + regex')
  // value stays a free input for the custom 'ls*' pattern (not a candidate)
  const valCtrl = flatKids(rules[0])[2]
  assert.equal(valCtrl.type, 'input', 'custom wildcard value is a free input')
  assert.equal(valCtrl.props.value, 'ls*', 'value preserved')
})

test('bundle: hook chips are single-select (no * all, no multi-select; ask locks to tools/pre-execute)', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setter(2)([
    {
      key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '',
      message: '', hooks: ['tools/pre-execute'], open: true,
      rules: [{ key: 11, field: 'highRisk', operator: 'eq', valueText: 'true' }],
    },
  ])

  const chip = (label) => {
    runtime.beginPass()
    runtime.setOverride(0, 'config')
    return collect(tree, (n) => n && n.children && n.children[0] === label && String(n.props?.className || '').includes('dsg-chip'))[0]
  }
  const hooksState = () => {
    runtime.beginPass()
    runtime.setOverride(0, 'config')
    // bundle runs in a vm sandbox: its arrays carry the sandbox Array.prototype,
    // so normalize to the host realm before deep-equal comparisons.
    return Array.from(runtime.states[2].value[0].hooks || [])
  }

  // 1. There is NO '* all' chip anymore.
  assert.equal(chip('* all'), undefined, 'no * all chip rendered')

  // 1b. The full native surface is offered — 9 seams, including the
  // observe-only lifecycle hooks and the monotonic guard invariant.
  assert.ok(chip('agent/session-start'), 'observe-only lifecycle hooks are offered')
  assert.ok(chip('subagent/end'), 'subagent lifecycle chips are offered')
  assert.ok(chip('tools/guard'), 'the monotonic guard invariant is offered')

  // 2. Single-select: clicking tools/result REPLACES tools/pre-execute.
  assert.deepEqual(hooksState(), ['tools/pre-execute'], 'start: only tools/pre-execute')
  chip('tools/result').props.onClick()
  assert.deepEqual(hooksState(), ['tools/result'], 'clicking another hook switches to it (single-select)')

  // 3. Clicking the selected chip keeps it selected (radio semantics).
  chip('tools/result').props.onClick()
  assert.deepEqual(hooksState(), ['tools/result'], 're-clicking the selected hook keeps it')

  // 4. ask policy: only tools/pre-execute is enabled; others are locked/disabled.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  runtime.setter(2)([
    {
      key: 1, id: 'p1', enabled: true, priority: '100', action: 'ask', mode: '',
      message: '', hooks: ['tools/post-execute'], open: true,
      rules: [{ key: 11, field: 'highRisk', operator: 'eq', valueText: 'true' }],
    },
  ])
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const chipOn = (label) => {
    const c = chip(label)
    return c && String(c.props.className || '').includes('dsg-chip-on')
  }
  // The editor renders the normalized single hook: ask auto-pins to
  // tools/pre-execute (selected) and disables the non-approval hooks.
  assert.ok(chipOn('tools/pre-execute'), 'ask policy renders tools/pre-execute selected')
  assert.ok(!chipOn('tools/post-execute'), 'tools/post-execute not selected for ask')
  const toolResult = chip('tools/post-execute')
  assert.equal(toolResult.props.disabled, true, 'tools/post-execute disabled for ask')
  const beforeTool = chip('tools/pre-execute')
  assert.equal(beforeTool.props.disabled, false, 'tools/pre-execute stays enabled for ask')
  // The persisted value is normalized to the single safe hook (not the raw draft).
  assert.deepEqual(Array.from(runtime.states[2].value[0].hooks || []), ['tools/post-execute'],
    'draft keeps the raw value until save; save-time normalizeHooks pins ask to tools/pre-execute')
})

test('bundle: observe-only hook narrows the policy action select to allow/warn (auto-clamp)', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  runtime.setter(2)([
    {
      key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '',
      message: '', hooks: ['tools/pre-execute'], open: true,
      rules: [{ key: 11, field: 'highRisk', operator: 'eq', valueText: 'true' }],
    },
  ])

  // The action select: the only dsg-select whose options carry action values
  // (the mode select offers ''/protect/monitor, rule rows are dsg-mono).
  const actionSelect = () => {
    runtime.beginPass()
    runtime.setOverride(0, 'config')
    return collect(tree, (n) => String(n.props?.className || '').includes('dsg-select')
      && collect(n, (o) => o && o.props && ['allow', 'warn'].includes(o.props.value)).length >= 2)[0]
  }
  const optionValues = () => collect(actionSelect(), (o) => o && o.type === 'option'
    && typeof o.props?.value === 'string').map((o) => o.props.value)
  const chip = (label) => {
    runtime.beginPass()
    runtime.setOverride(0, 'config')
    return collect(tree, (n) => n && n.children && n.children[0] === label && String(n.props?.className || '').includes('dsg-chip'))[0]
  }
  const notes = () => {
    runtime.beginPass()
    runtime.setOverride(0, 'config')
    return collect(tree, (n) => n && String(n.props?.className || '').split(' ').includes('dsg-note')
      && typeof n.props.children === 'string').map((n) => n.props.children)
  }

  // 1. Control: an enforceable hook keeps the full four-action surface.
  assert.deepEqual(optionValues(), ['allow', 'block', 'ask', 'warn'], 'enforceable hook offers all four actions')
  assert.equal(actionSelect().props.title, undefined, 'no observe-only tooltip on an enforceable hook')
  assert.equal(notes().some((s) => s.includes('the disposition narrows')), false, 'no observe-only note on an enforceable hook')

  // 2. Moving onto an observe-only seam auto-clamps block → warn (the
  // strictest verdict that seam can deliver; ask would re-pin the binding to
  // the approval seam, so the clamp keeps the user's hook choice).
  chip('tools/result').props.onClick()
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  assert.equal(runtime.states[2].value[0].action, 'warn', 'clicking an observe-only chip clamps block down to warn')

  // 3. The select narrows to allow/warn, carries the observe-only tooltip and
  // an explanatory note (draft stays editable; save-time clamp also guards).
  assert.deepEqual(optionValues(), ['allow', 'warn'], 'observe-only hook offers only allow/warn')
  assert.ok(String(actionSelect().props.title || '').includes('never interrupts the run'), 'observe-only tooltip on the select')
  assert.ok(notes().some((s) => s.includes('the disposition narrows')), 'observe-only note explains the restriction')

  // 4. A hand-loaded observe-only+block draft (e.g. JSON import) clamps the
  // SELECT to the narrowed surface (value falls back to warn; options stay 2).
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  runtime.setter(2)([
    {
      key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '',
      message: '', hooks: ['subagent/start'], open: true,
      rules: [{ key: 11, field: 'highRisk', operator: 'eq', valueText: 'true' }],
    },
  ])
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  assert.deepEqual(optionValues(), ['allow', 'warn'], 'observe-only draft still offers only allow/warn')
  assert.equal(actionSelect().props.value, 'warn', 'a raw block value displays clamped to warn')

  // 5. Save-time serialization clamps too: a block draft bound to an
  // observe-only seam serializes as warn on that seam.
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const jsonBtn2 = collect(tree, (n) => n && n.children && n.children[0] === 'JSON view' && String(n.props?.className || '').includes('dsg-action'))[0]
  jsonBtn2.props.onClick()
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const ta2 = collect(tree, (n) => String(n.props?.className || '').includes('dsg-textarea'))[0]
  assert.ok(/"action":\s*"warn"/.test(ta2.props.value), 'observe-only block draft serializes clamped to warn')
})

test('bundle: save-time serialize pins ask policies to tools/pre-execute (single-hook contract)', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  // Draft carries an ask policy whose raw hooks are a forbidden value; the
  // JSON serializer must normalize it to the single safe hook.
  runtime.setter(2)([
    {
      key: 1, id: 'ask-curl', enabled: true, priority: '100', action: 'ask', mode: '',
      message: 'approve curl', hooks: ['tools/post-execute'], open: true,
      rules: [{ key: 11, field: 'toolName', operator: 'eq', valueText: 'curl' }],
    },
    {
      key: 2, id: 'block-x', enabled: true, priority: '50', action: 'block', mode: '',
      message: '', hooks: ['*'], open: true,
      rules: [{ key: 21, field: 'toolName', operator: 'eq', valueText: 'bash' }],
    },
  ])

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const jsonBtn = collect(tree, (n) => n && n.children && n.children[0] === 'JSON view' && String(n.props?.className || '').includes('dsg-action'))[0]
  assert.ok(jsonBtn, 'JSON view button present')
  jsonBtn.props.onClick()

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const ta = collect(tree, (n) => String(n.props?.className || '').includes('dsg-textarea'))[0]
  assert.ok(ta, 'raw JSON textarea rendered')
  const serialized = ta.props.value
  // ask policy: raw tools/post-execute must be pinned to tools/pre-execute.
  assert.ok(!/ask-curl"[\s\S]*tools\/post-execute/.test(serialized), 'ask policy does not keep a non-approval hook')
  assert.ok(/ask-curl"[\s\S]*tools\/pre-execute/.test(serialized), 'ask policy serializes to tools/pre-execute')
  // legacy * all: block policy serializes to the default single hook.
  assert.ok(!/block-x"[\s\S]*\*/.test(serialized), 'legacy * all does not survive serialization')
  assert.ok(/block-x"[\s\S]*tools\/pre-execute/.test(serialized), 'legacy * all collapses to tools/pre-execute')
})

test('bundle: regex operator appears for text fields and preserves the pattern value', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setter(2)([
    {
      key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '',
      message: '', hooks: ['agent/pre-step'], open: true,
      rules: [{ key: 11, field: 'content', operator: 'regex', valueText: 'BEGIN (RSA |EC )?PRIVATE KEY' }],
    },
  ])
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const rules = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-rule'))
  assert.equal(rules.length, 1, 'one rule row')
  const flatKids = (n) => (n.children || []).filter(Boolean).flat()
  const opOptions = (n) => flatKids(flatKids(n)[1]).map((o) => o.props.value)
  assert.deepEqual(opOptions(rules[0]), ['eq', 'neq', 'contains', 'in', 'matches', 'regex'], 'text field offers regex')
  const valCtrl = flatKids(rules[0])[2]
  assert.equal(valCtrl.type, 'input', 'regex pattern is a free input')
  assert.equal(valCtrl.props.value, 'BEGIN (RSA |EC )?PRIVATE KEY', 'pattern preserved verbatim')
})

test('bundle: field dropdown follows policy hooks (scoped fields hidden when irrelevant)', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }
  const flatKids = (n) => (n.children || []).filter(Boolean).flat()
  // Recursively collect every option value (fields are grouped under <optgroup>
  // inside a .dsg-fcell wrapper now).
  const fieldOptions = (n) => {
    const out = []
    const walk = (node) => {
      if (node && node.props && typeof node.props.value === 'string' && node.props.value) out.push(node.props.value)
      if (Array.isArray(node)) return node.forEach(walk)
      if (node && node.children) node.children.forEach((c) => walk(c))
    }
    walk(n)
    return out.filter((v) => v !== '__custom__')
  }

  let openedOnce = false
  const openPolicyWith = (hooks) => {
    runtime.beginPass()
    runtime.setOverride(0, 'config')
    if (!openedOnce) {
      const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
      closed[0].props.onClick()
      openedOnce = true
    }
    runtime.beginPass()
    runtime.setter(2)([
      {
        key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '',
        message: '', hooks, open: true,
        rules: [{ key: 11, field: '', operator: 'eq', valueText: '' }],
      },
    ])
    runtime.beginPass()
    runtime.setOverride(0, 'config')
    const rules = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-rule'))
    const fcell = (rules[0].children || []).filter(Boolean)[0]
    return fieldOptions(fcell)
  }

  // tools/pre-execute scope: tool fields present, prompt fields hidden.
  const toolFields = openPolicyWith(['tools/pre-execute'])
  assert.ok(toolFields.includes('command'), 'tool hook offers command')
  assert.ok(toolFields.includes('toolName'), 'tool hook offers toolName')
  assert.ok(!toolFields.includes('content'), 'tool hook hides content (prompt-only)')
  assert.ok(!toolFields.includes('userIntentRisk'), 'tool hook hides userIntentRisk')
  assert.ok(toolFields.includes('raw'), 'raw payload field is universal')
  assert.ok(toolFields.includes('eventType'), 'eventType is universal')

  // prompt scope: prompt fields present, tool fields hidden.
  const promptFields = openPolicyWith(['agent/pre-step'])
  assert.ok(promptFields.includes('content'), 'prompt hook offers content')
  assert.ok(promptFields.includes('userIntentRisk'), 'prompt hook offers userIntentRisk')
  assert.ok(!promptFields.includes('command'), 'prompt hook hides command (tool-only)')
  assert.ok(!promptFields.includes('toolName'), 'prompt hook hides toolName')
  assert.ok(promptFields.includes('raw'), 'raw stays universal')

  // tools/post-execute scope: result fields present, tool + prompt hidden.
  const resultFields = openPolicyWith(['tools/post-execute'])
  assert.ok(resultFields.includes('toolResultText'), 'result hook offers toolResultText')
  assert.ok(resultFields.includes('toolResultFlags'), 'result hook offers toolResultFlags')
  assert.ok(!resultFields.includes('command'), 'result hook hides command (tool-only)')
  assert.ok(!resultFields.includes('content'), 'result hook hides content (prompt-only)')
  assert.ok(resultFields.includes('raw'), 'raw stays universal')
})

test('bundle: a scoped-out field stays a dropdown, pinned as out-of-scope instead of degrading to input', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  // Policy already has a `content` rule but its hook scope changed to a tool hook.
  runtime.setter(2)([
    {
      key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '',
      message: '', hooks: ['tools/pre-execute'], open: true,
      rules: [{ key: 11, field: 'content', operator: 'contains', valueText: 'ignore' }],
    },
  ])
  runtime.beginPass()
  runtime.setOverride(0, 'config')
  const rules = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-rule'))
  const fcell = (rules[0].children || []).filter(Boolean)[0]
  const select = (fcell.children || []).filter(Boolean).find((c) => c.type === 'select')
  assert.ok(select, 'scoped-out field still renders as a dropdown')
  // The `content` option is pinned at the top labelled out of scope.
  const allOptions = (() => {
    const out = []
    const walk = (n) => {
      if (n && n.type === 'option' && n.props) out.push(n)
      if (Array.isArray(n)) return n.forEach(walk)
      if (n && n.children) n.children.forEach((c) => walk(c))
    }
    walk(select)
    return out
  })()
  assert.ok(allOptions.some((o) => o.props.value === 'content'), 'scoped-out field value stays selectable')
  const pinned = allOptions.find((o) => o.props.value === 'content')
  assert.ok(pinned, 'scoped-out field pinned as an option')
  assert.ok(String(pinned.children[0]).includes('out of scope'), 'pinned option labelled out of scope')
  // help button still explains it
  const help = (fcell.children || []).filter(Boolean).find((c) => c.props && c.props.className === 'dsg-help')
  assert.ok(help && help.props['data-hint'], 'help button explains the field')
})

test('bundle: empty hook-surface groups are hidden in the field dropdown', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }
  const groupLabels = (select) => {
    const out = []
    const walk = (n) => { if (n && n.type === 'optgroup') out.push(n.props.label); if (Array.isArray(n)) return n.forEach(walk); if (n && n.children) n.children.forEach(walk) }
    walk(select)
    return out
  }
  let openedOnce = false
  const openPolicyWith = (hooks) => {
    runtime.beginPass(); runtime.setOverride(0, 'config')
    if (!openedOnce) {
      const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
      closed[0].props.onClick(); openedOnce = true
    }
    runtime.beginPass()
    runtime.setter(2)([{ key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '', message: '', hooks, open: true, rules: [{ key: 11, field: '', operator: 'eq', valueText: '' }] }])
    runtime.beginPass(); runtime.setOverride(0, 'config')
    const rules = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-rule'))
    const fcell = (rules[0].children || []).filter(Boolean)[0]
    return fcell.children.filter(Boolean).find((c) => c.type === 'select')
  }

  // tools/pre-execute → only Universal + Tool call (result/prompt empty → hidden)
  let sel = openPolicyWith(['tools/pre-execute'])
  assert.deepEqual(groupLabels(sel), ['Universal', 'Tool call'], 'empty groups hidden for tools/pre-execute')

  // tools/post-execute → only Universal + Tool result
  runtime.beginPass(); runtime.setOverride(0, 'config')
  sel = openPolicyWith(['tools/post-execute'])
  assert.deepEqual(groupLabels(sel), ['Universal', 'Tool result'], 'empty groups hidden for tools/post-execute')

  // agent/pre-step → only Universal + Prompt
  runtime.beginPass(); runtime.setOverride(0, 'config')
  sel = openPolicyWith(['agent/pre-step'])
  assert.deepEqual(groupLabels(sel), ['Universal', 'Prompt / content'], 'empty groups hidden for agent/pre-step')

  // tools/result → Universal + Tool call + Tool result (prompt hidden)
  runtime.beginPass(); runtime.setOverride(0, 'config')
  sel = openPolicyWith(['tools/result'])
  assert.deepEqual(groupLabels(sel), ['Universal', 'Tool call', 'Tool result'], 'tools/result shows tool + result groups')
})

test('bundle: help button wires JS tooltip handlers (full hint, escapes overflow clipping)', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass(); runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setter(2)([
    {
      key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '',
      message: '', hooks: ['tools/pre-execute'], open: true,
      rules: [{ key: 11, field: 'command', operator: 'eq', valueText: 'rm -rf' }],
    },
  ])
  runtime.beginPass(); runtime.setOverride(0, 'config')
  const rules = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-rule'))
  const fcell = (rules[0].children || []).filter(Boolean)[0]
  const help = (fcell.children || []).filter(Boolean).find((c) => c.props && c.props.className === 'dsg-help')
  assert.ok(help, 'help button present')
  assert.equal(typeof help.props.onMouseEnter, 'function', 'JS tooltip show handler wired')
  assert.equal(typeof help.props.onMouseLeave, 'function', 'JS tooltip hide handler wired')
  // the long command hint travels verbatim into the floating tip
  assert.match(help.props['data-hint'], /wildcards/, 'command hint preserved in full')
})

test('bundle: Mode field has a help button with a full defense-mode hint', () => {
  const runtime = makeRuntime()
  const GuardPanel = mount(loadBundle(runtime))
  const tree = { type: GuardPanel, props: {} }

  runtime.beginPass(); runtime.setOverride(0, 'config')
  const closed = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))
  closed[0].props.onClick()
  runtime.beginPass()
  runtime.setter(2)([
    { key: 1, id: 'p1', enabled: true, priority: '100', action: 'block', mode: '', message: '', hooks: ['tools/pre-execute'], open: true, rules: [{ key: 11, field: 'command', operator: 'eq', valueText: 'x' }] },
  ])
  runtime.beginPass(); runtime.setOverride(0, 'config')
  // find the label row (dsg-flabel) that holds the 'Mode' label
  const flabels = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-flabel'))
  const modeRow = flabels.find((f) => {
    const kids = (f.children || []).filter(Boolean)
    const label = kids.find((k) => k.type === 'span' && String(k.props?.className || '').includes('dsg-label'))
    return label && label.children[0] === 'Mode'
  })
  assert.ok(modeRow, 'Mode label wrapped in a label row')
  const kids = (modeRow.children || []).filter(Boolean)
  const help = kids.find((c) => c.props && c.props.className === 'dsg-help')
  assert.ok(help, 'Mode field has a help button')
  assert.match(help.props['data-hint'], /monitor/, 'hint explains monitor downgrade')
  assert.equal(typeof help.props.onMouseEnter, 'function', 'JS tooltip wired')
})

/**
 * Mount with a stub that records the `conversation.view` registration lifecycle
 * and returns the settings-section component. `slots.inject` invokes the
 * factory immediately (as the real registry does once the declaration is on
 * the ledger) and `slots.register` returns a disposer that flips the entry's
 * presence flag, mirroring the real slot-core unload cascade.
 */
function mountViewAware(exportsObj, fetchOverride) {
  const seats = {}
  const live = {} // slot name -> number of currently active registrations
  const registeredSpecs = {} // slot name -> all specs ever registered
  let setPrefsCalls = []
  exportsObj.apply({
    slots: {
      inject(name, factory) {
        seats[name] = factory
        // The real registry runs the factory once its target slot is declared.
        const disposers = factory()
        seats['__disposers__' + name] = disposers
      },
      register(spec, component) {
        live[spec.name] = (live[spec.name] || 0) + 1
        registeredSpecs[spec.name] = registeredSpecs[spec.name] || []
        registeredSpecs[spec.name].push({ spec, component })
        return () => { live[spec.name] -= 1 }
      },
    },
    effect() {},
  })
  // Wire the preferences fetch so boot load and toggles resolve.
  if (fetchOverride) exportsObj._fetchOverride = fetchOverride
  return { seats, live, registeredSpecs, setPrefsCalls }
}

/** Recursively collect every rendered text leaf of a component tree. */
function collectText(node, texts) {
  if (node === null || node === undefined || typeof node === 'boolean') return
  if (Array.isArray(node)) { for (const n of node) collectText(n, texts); return }
  if (typeof node === 'string' || typeof node === 'number') { texts.push(String(node)); return }
  const { type, props, children } = node
  if (typeof type === 'function') collectText(type(props), texts)
  else for (const c of children) collectText(c, texts)
}

test('bundle: conversation.view entry registers GuardReviewView and is removed when showTab turns off', async () => {
  const runtime = makeRuntime()
  const myRows = [
    { sessionId: 's1', seq: 6, time: 1720000000000, hook: 'tools/pre-execute', outcome: 'deny', turn: 1, step: 1, tool: 'bash', callId: 'c1', policyId: 'p1', message: 'blocked bash', detail: { kind: 'tool', turn: 1, step: 1, arguments: '{}' } },
  ]
  // Seed the per-session verdict payload BEFORE the bundle loads (the sandbox
  // captures the fetch reference at load time).
  runtime.fetch = async (url) => ({
    ok: true,
    json: async () => (String(url).includes('sessionId=s1') ? myRows : []),
  })
  const exportsObj = loadBundle(runtime)
  const { seats, live, registeredSpecs } = mountViewAware(exportsObj)
  // The view inject factory ran synchronously during apply (showTab defaults on).
  const specs = registeredSpecs['conversation.view'] || []
  assert.equal(specs.length, 1, 'conversation.view entry registered at boot')
  assert.equal(specs[0].spec.id, 'security-guard')
  assert.equal(specs[0].spec.name, 'conversation.view')
  assert.ok(specs[0].component, 'view component registered')
  assert.equal(live['conversation.view'], 1)
  // Render the tab body: seed the session verdict rows through the component's
  // own rows state (local state, index 0 — the view's first useState) so the
  // summary and row render without running the 4s polling effect (which would
  // leave a live interval and stall the test runner).
  const tree = { type: specs[0].component, props: { sessionId: 's1' } }
  const texts = []
  collectText(tree, texts)
  runtime.setter(0)(myRows)
  runtime.beginPass()
  texts.length = 0
  collectText(tree, texts)
  assert.ok(texts.some((s) => /Blocked 1/.test(s)), 'summary counts rendered')
  assert.ok(texts.some((s) => /blocked bash/.test(s)), 'session verdict message rendered')
  // The verdict list renders as a table with a sticky column header.
  runtime.beginPass()
  const viewTree = { type: specs[0].component, props: { sessionId: 's1' } }
  const table = collect(viewTree, (n) => String(n.props?.className || '').split(' ').includes('dsg-table'))[0]
  assert.ok(table, 'review list renders as a table')
  const headTh = collect(table, (n) => n.type === 'th').map((n) => (n.children || [])[0])
  assert.ok(headTh.includes('Time') && headTh.includes('Result'), 'table header columns rendered')
  assert.ok(headTh.includes('Hook') && headTh.includes('Tool') && headTh.includes('Info'), 'remaining table columns rendered')
  const rows = collect(table, (n) => String(n.props?.className || '').split(' ').includes('dsg-t-row'))
  assert.equal(rows.length, 1, 'one verdict body row rendered')
  const rowTexts = []
  collectText(rows[0], rowTexts)
  assert.ok(rowTexts.some((s) => /blocked bash/.test(s)), 'row carries the verdict message')
  assert.ok(rowTexts.some((s) => /bash/.test(s)), 'row carries the tool column')
  assert.ok(rowTexts.some((s) => /Blocked/.test(s)), 'row carries the outcome column')

  // Toggle the setting off via the settings section checkbox → entry removed.
  const sectionSpecs = registeredSpecs['settings.section'] || []
  assert.equal(sectionSpecs.length, 1, 'settings section registered')
  const section = sectionSpecs[0].component
  // The settings section is an independent component: its hook indices would
  // otherwise collide with the view's (both start at slot 0), so give it a
  // fresh hook store for this pass.
  runtime.states.length = 0
  runtime.beginPass()
  // The display-only settings live inside the collapsed Interface & language
  // card; open
  // that card (the one whose head reads Interface & language) like a user
  // would so the toggle below is reachable. Match by title text: the debug
  // card added later is ALSO collapsed by default, so aria-expanded alone
  // is no longer a unique selector.
  const textOf = (node) => {
    let out = ''
    const walk = (n) => {
      if (n === null || n === undefined || typeof n === 'boolean') return
      if (Array.isArray(n)) { n.forEach(walk); return }
      if (typeof n === 'string' || typeof n === 'number') { out += String(n); return }
      const { type, props, children } = n
      if (typeof type === 'function') { walk(type(props)); return }
      children.forEach(walk)
    }
    walk(node)
    return out
  }
  let uiCardHead
  collect({ type: section, props: {} }, (n) => {
    if (n && n.props && String(n.props.className || '').split(' ').includes('dsg-card-head')
      && n.props['aria-expanded'] === false && textOf(n).includes('Interface')) uiCardHead = n
  })
  assert.ok(uiCardHead, 'display-settings card head rendered (collapsed by default)')
  uiCardHead.props.onClick()
  runtime.beginPass()
  let checkbox
  collect({ type: section, props: {} }, (n) => {
    if (n && n.props && n.props.type === 'checkbox' && n.props['aria-label'] === 'Show session review tab') checkbox = n
  })
  assert.ok(checkbox, 'showTab toggle rendered in settings')
  checkbox.props.onChange({ target: { checked: false } })
  runtime.beginPass()
  assert.equal(live['conversation.view'], 0, 'view entry unregistered after toggle off')
})

test('bundle: subscribing settings locale etc. does not disturb the view entry label', () => {
  const runtime = makeRuntime()
  const exportsObj = loadBundle(runtime)
  const { registeredSpecs } = mountViewAware(exportsObj)
  const spec = (registeredSpecs['conversation.view'] || [])[0]
  assert.ok(spec, 'view entry present')
  // The label is a thunk so it can follow locale without re-registration.
  assert.equal(typeof spec.spec.label, 'function')
  assert.equal(spec.spec.order, 20)
})

test('bundle: view without a sessionId must never fetch the all-session trail', async () => {
  const runtime = makeRuntime()
  let verdictFetches = 0
  runtime.fetch = async (url, opts) => {
    // The resolved-locale report POST is payload plumbing, not the verdict trail.
    if (String(url).includes('/guard/api/lang/resolved')) return { ok: true, json: async () => ({ ok: true }) }
    if (String(url).includes('/guard/api/verdicts')) verdictFetches += 1
    return { ok: true, json: async () => [] }
  }
  const exportsObj = loadBundle(runtime)
  const { registeredSpecs } = mountViewAware(exportsObj)
  const Spec = (registeredSpecs['conversation.view'] || [])[0].component
  // No sessionId prop: the tab must render an empty state and not leak every
  // session's verdicts (the shield panel is the only unfiltered consumer).
  const tree = { type: Spec, props: {} }
  const texts = []
  for (let i = 0; i < 2; i++) {
    runtime.beginPass()
    collectText(tree, texts)
  }
  assert.equal(verdictFetches, 0, 'no verdict fetch fired without a session id')
})

/** True when the element node carries `name` among its classes. */
function hasClass(n, name) {
  return String((n.props && n.props.className) || '').split(' ').includes(name)
}

/** Mount that captures the `settings.section` component (LangSection). */
function mountSettingsSection(exportsObj) {
  let section = null
  exportsObj.apply({
    slots: {
      inject(name, factory) { if (name === 'settings.section') factory() },
      register(spec, component) { if (spec && spec.name === 'settings.section') section = component },
    },
    effect() {},
  })
  return section
}

/**
 * Mount the panel and land on the Model Review tab with the panel open — the
 * review prompts (moved out of the settings section) are exercised there.
 * Returns a renderPass() flattening one pass over the open panel. The tab is
 * GuardPanel's first useState (hook slot 0): the override pins the initial
 * value, which then persists across passes in the state map.
 */
async function mountModelTab(exportsObj, runtime) {
  const GuardPanel = mount(exportsObj, runtime)
  // Run the boot effects (loadPrefs + locale report) so the seeded GET /prefs
  // populates the model-review store before assertions.
  for (const fn of runtime.effects.slice()) { fn() }
  runtime.beginPass()
  runtime.setOverride(0, 'model')
  const tree = { type: GuardPanel, props: {} }
  const hdrBtn = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-hdr'))[0]
  assert.ok(hdrBtn && typeof hdrBtn.props.onClick === 'function', 'shield toggle button present')
  hdrBtn.props.onClick()
  // The boot prefs load (loadPrefs → guardApi.getPrefs) is async; the seeded
  // fetch resolves on a microtask. Flush it so the model-review store carries
  // the seeded baselineTemplates / templates before the first assertion.
  await new Promise((resolve) => setTimeout(resolve, 0))
  // beginPass resets the hook cursor before every render (state slots persist;
  // only overrides clear) — same pattern the other panel tests follow.
  runtime.beginPass()
  const render = () => {
    runtime.beginPass()
    const out = []
    const expand = (node) => {
      if (node === null || node === undefined || typeof node === 'boolean') return
      if (Array.isArray(node)) { node.forEach(expand); return }
      if (typeof node === 'string' || typeof node === 'number') return
      const { type, props, children } = node
      if (typeof type === 'function') { expand(type(props)); return }
      out.push(node)
      children.forEach(expand)
    }
    expand({ type: GuardPanel, props: {} })
    return out
  }
  return { render, tree }
}

/** Expand the baseline group + the FIRST baseline card body (group starts
 * expanded; the card bodies start open too, so this only closes a manual
 * prior collapse — idempotent). Returns whether any baseline card rendered. */
function expandBaseline(tree, render) {
  const toggle = collect(tree, (n) => String(n.props?.className || '').split(' ').includes('dsg-group-toggle'))[0]
  if (toggle && typeof toggle.props.onClick === 'function' && String(toggle.children.join('')).includes('\u25b8')) {
    toggle.props.onClick()
  }
  const baseArrow = render().filter((n) => String(n.props?.className || '').includes('dsg-pcard-base'))
    .flatMap((card) => collect(card, (n) => n && n.props && String(n.props.title || '') === 'Expand'))[0]
  if (baseArrow) baseArrow.props.onClick()
  return Boolean(baseArrow)
}

test('bundle: the settings section points to the shield panel for review prompts', () => {
  const runtime = makeRuntime()
  const exportsObj = loadBundle(runtime)
  const LangSection = mountSettingsSection(exportsObj)
  assert.equal(typeof LangSection, 'function', 'settings.section registers a component')
  runtime.beginPass()
  const out = []
  const expand = (node) => {
    if (node === null || node === undefined || typeof node === 'boolean') return
    if (Array.isArray(node)) { node.forEach(expand); return }
    if (typeof node === 'string' || typeof node === 'number') return
    const { type, props, children } = node
    if (typeof type === 'function') { expand(type(props)); return }
    out.push(node)
    children.forEach(expand)
  }
  expand({ type: LangSection, props: {} })
  const find = (nodes, cls) => nodes.filter((n) => hasClass(n, cls))
  // The review-prompt preview + editor moved to the shield panel's Model Review
  // tab: the settings section carries no trace of them — no preview, no
  // editor, not even a pointer note (cleaned up after the move).
  assert.equal(find(out, 'dsg-textarea').length, 0, 'no prompt preview left on the settings page')
  assert.equal(find(out, 'dsg-modal-mask').length, 0, 'no editor modal on the settings page')
  assert.equal(find(out, 'dsg-modal').length, 0, 'no editor dialog on the settings page')
  const labels = find(out, 'dsg-lang-label').map((n) => n.children.join(''))
  assert.ok(!labels.includes('审查提示词'), 'no orphaned review-prompt label on the settings page')
})

test('bundle: baseline template cards are read-only and gated by per-card enabled', async () => {
  // Record the prefs POSTs so persistence (not just local state) is verifiable.
  const posts = []
  const runtime = makeRuntime()
  const baseFetch = runtime.fetch
  const seededBaselines = [
    { id: 'malicious-intent-detection', name: '恶意意图检测', hooks: ['agent/pre-step'], enabled: true, prompt: 'USER query risk prompt'.repeat(200) },
    { id: 'risk-instruction-detection', name: '风险指令检测', hooks: ['tools/pre-execute'], enabled: true, prompt: 'AGENT behavior risk prompt'.repeat(200) },
    { id: 'intent-drift-detection', name: '意图偏离检测', hooks: ['tools/pre-execute'], enabled: false, prompt: 'INTENT drift prompt'.repeat(200) },
  ]
  runtime.fetch = async (url, opts) => {
    const u = String(url)
    if (u.includes('/guard/api/prefs') && (!opts || opts.method !== 'POST')) {
      // Boot GET: seed baselineTemplates plus the rest of the prefs doc.
      return { ok: true, json: async () => ({
        locale: 'auto', guardEnabled: true, rulesEnabled: true,
        modelReview: { enabled: true, mode: 'session', baselineTemplates: seededBaselines, templates: [], baseUrl: '', apiKey: '', model: '', timeoutMs: 12000, protocol: 'openai-chat', thinking: 'default' },
      }) }
    }
    if (u.includes('/guard/api/prefs')) {
      posts.push(opts && opts.body ? JSON.parse(String(opts.body)) : null)
      return { ok: true, json: async () => ({ ok: true }) }
    }
    return baseFetch(url, opts)
  }
  const exportsObj = loadBundle(runtime)
  const { render: renderPass, tree: modelTree } = await mountModelTab(exportsObj, runtime)
  const find = (nodes, cls) => nodes.filter((n) => hasClass(n, cls))
  const flush = () => new Promise((resolve) => setTimeout(resolve, 0))

  // Open the baseline group + the first card's body for the read-only
  // assertions below (each card collapses independently, like base policies).
  await expandBaseline(modelTree, renderPass)
  // The group header reports the live card count (substituted, not the raw
  // {count} placeholder — bug: the count was passed without a value).
  const groupCount = renderPass().filter((n) => n && n.props && String(n.props.className || '').includes('dsg-group-count'))[0]
  assert.ok(groupCount, 'baseline group count renders')
  assert.equal(String(groupCount.children.join('')).trim(), '3 templates',
    'the baseline group count is substituted with the real card count')
  // The baseline group renders THREE read-only cards, one per shipped audit
  // prompt, each with its fixed hook binding (read-only chips, no onClick).
  const baseCards = () => find(renderPass(), 'dsg-pcard-base')
  assert.equal(baseCards().length, 3, 'three baseline template cards')
  // Each card head: badge + enable checkbox + fixed name; no delete/order/edit.
  for (const card of baseCards()) {
    const head = collect(card, (n) => n && n.props && String(n.props.className || '').includes('dsg-pcard-head'))[0]
    assert.ok(head, 'card head renders')
    const checks = collect(head, (n) => n && n.type === 'input' && n.props.type === 'checkbox')
    assert.equal(checks.length, 1, 'exactly one enabled checkbox per baseline card')
    const badge = collect(card, (n) => n && n.props && String(n.props.className || '').split(' ').includes('dsg-badge-base'))
    assert.equal(badge.length, 1, 'built-in badge on every baseline card')
    assert.equal(collect(card, (n) => n.type === 'button' && String(n.children.join('')) === '\u2715').length, 0,
      'baseline cards are not deletable')
    assert.equal(collect(card, (n) => n.type === 'button' && String(n.children.join('')).startsWith('\u270e ')).length, 0,
      'baseline prompts are read-only (no edit affordance)')
  }

  // The body (open after mountModelTab expanded the first card) shows the
  // fixed hook binding as read-only chips and a read-only prompt preview.
  const first = baseCards()[0]
  const firstChips = collect(first, (n) => n && n.props && String(n.props.className || '').split(' ').includes('dsg-chip'))
  assert.ok(firstChips.length > 0, 'the baseline card shows its fixed hook binding')
  assert.ok(firstChips.every((c) => typeof c.props.onClick !== 'function'),
    'baseline hook chips are read-only (no toggle)')
  const preview = collect(first, (n) => n && n.type === 'textarea')[0]
  assert.ok(preview, 'a read-only prompt preview renders on the baseline card')
  assert.equal(preview.props.readOnly, true, 'baseline prompt box is read-only')
  assert.equal(preview.props.onChange, undefined, 'no inline write path on the baseline preview')

  // The card's View button opens the read-only full-prompt viewer (no edit).
  const viewBtn = collect(first, (n) => n && n.type === 'button' && String(n.children.join('')).startsWith('\u{1F441} '))[0]
  assert.ok(viewBtn, 'baseline card carries a View affordance')
  assert.ok(viewBtn.props.onClick, 'view opens a dialog')
  viewBtn.props.onClick()
  const viewMask = find(renderPass(), 'dsg-modal-mask')[0]
  assert.ok(viewMask, 'the View click opens the prompt dialog')
  const viewArea = collect(viewMask, (n) => n && n.type === 'textarea')[0]
  assert.ok(viewArea, 'the viewer renders the prompt text')
  assert.equal(viewArea.props.readOnly, true, 'the viewer is read-only')
  assert.ok(String(viewArea.props.value).includes('USER query risk prompt'), 'the viewer shows the baseline prompt')
  const backdrop = { x: 1 }
  find(renderPass(), 'dsg-modal-mask')[0].props.onMouseDown({ target: backdrop, currentTarget: backdrop })
  assert.equal(find(renderPass(), 'dsg-modal-mask').length, 0, 'the viewer closes on backdrop')

  // ── Baseline card mirrors the rule-config baseline policy card: the ⚠
  // read-only badge sits where the delete button sits on a custom card, and
  // the expanded body carries a read-only disposition chip row + the FULL seam
  // surface (all 9 hooks, bound ones lit, all inert) + the read-only prompt.
  const firstHead = collect(first, (n) => n && n.props && String(n.props.className || '').includes('dsg-pcard-head'))[0]
  const warnBadge = collect(firstHead, (n) => n && n.props && String(n.props.className || '').includes('dsg-meta'))[0]
  assert.ok(warnBadge, 'baseline card head carries the ⚠ meta badge')
  assert.ok(String(warnBadge.props.title || '').includes('read-only'), 'the ⚠ badge explains the read-only contract on hover')
  // Disposition action: a read-only dropdown in the HEAD (visible without
  // expanding, like the rule-config action select), listing the shipped
  // verdict actions with the most severe one selected.
  const selects = collect(first, (n) => n && n.type === 'select')
  assert.equal(selects.length, 1, 'exactly one disposition dropdown (head only, no body copy)')
  assert.ok(selects[0] === collect(firstHead, (n) => n && n.type === 'select')[0],
    'the disposition dropdown sits in the collapsed head')
  assert.equal(selects[0].props.disabled, true, 'the disposition dropdown is read-only')
  assert.deepEqual(collect(selects[0], (n) => n && n.type === 'option').map((o) => o.props.value), ['allow', 'warn', 'block'],
    'Malicious Intent Detection offers its three verdict actions (allow/warn/block)')
  assert.equal(selects[0].props.value, 'block', 'the most severe action is the selected value')
  const hookChips = collect(first, (n) => n && n.type === 'button' && String(n.props.className || '').split(' ').includes('dsg-chip'))
  assert.equal(hookChips.length, 9, 'the expanded body offers all 9 seams (not just the binding)')
  assert.ok(hookChips.every((c) => c.props.disabled === true), 'baseline hook chips are inert')
  assert.equal(hookChips.filter((c) => String(c.props.className).includes('dsg-chip-on')).length, 1,
    'exactly the bound seam is lit')
  assert.equal(hookChips.find((c) => String(c.props.className).includes('dsg-chip-on')).children.join(''), 'agent/pre-step',
    'the lit seam is the shipped binding')
  // The inline read-only note is gone (the ⚠ badge + textarea title carry it).
  assert.equal(collect(first, (n) => n && n.props && String(n.props.className || '').includes('dsg-note')).length, 0,
    'no inline read-only note on the baseline card')

  // ── Toggling a card's enabled switch lands in the DRAFT: no POST until
  // Save, which persists the whole baselineTemplates array (only `enabled`
  // differs on the affected card). The auto locale resolves to en here, so
  // the shipped Chinese stored names localize: the card is found by its
  // English label, and no card shows the raw stored Chinese name.
  const cardLabel = (card) => String(collect(card, (n) => n && n.props && String(n.props.className || '').includes('dsg-lang-label'))[0].children.join(''))
  assert.ok(baseCards().some((card) => cardLabel(card) === 'Intent Drift Detection'),
    'the baseline card name localizes to the panel language (en)')
  assert.ok(!baseCards().some((card) => cardLabel(card) === '意图偏离检测'),
    'the raw stored Chinese name never renders verbatim in an en panel')
  const offCard = baseCards().find((card) => cardLabel(card) === 'Intent Drift Detection')
  assert.ok(offCard, 'the disabled card is present')
  const box = collect(offCard, (n) => n && n.type === 'input' && n.props.type === 'checkbox')[0]
  assert.equal(box.props.checked, false, 'the seeded disabled card renders unchecked')
  box.props.onChange({ target: { checked: true } })
  await flush()
  assert.equal(posts.length, 0, 'the toggle stays in the draft (no instant POST)')
  assert.ok(find(renderPass(), 'dsg-banner')[0], 'the dirty draft shows the unsaved-changes banner')
  // Save + Reload live in the PINNED footer (a sibling of dsg-body), not in
  // the scrollable tab body.
  const saveBtn = find(renderPass(), 'dsg-action').filter((n) => n.children.join('') === 'Save')[0]
  assert.ok(saveBtn, 'the model tab carries a Save button')
  const passNodes = renderPass()
  const bodyNode = passNodes.filter((n) => hasClass(n, 'dsg-body'))[0]
  const footerNode = passNodes.filter((n) => hasClass(n, 'dsg-footer'))[0]
  assert.ok(footerNode, 'the model tab renders a pinned dsg-footer')
  assert.ok(footerNode !== bodyNode, 'the footer is a sibling of the scrollable body')
  assert.ok(collect(footerNode, (n) => n && n.type === 'button').some((n) => n.children.join('') === 'Save'),
    'the Save button lives in the footer')
  assert.ok(!collect(bodyNode, (n) => n && n.type === 'button').some((n) => n.children.join('') === 'Save'),
    'the scrollable body carries no Save button')
  saveBtn.props.onClick()
  await flush()
  const baselinePost = posts.map((p) => p && p.modelReview).find((mr) => mr && Array.isArray(mr.baselineTemplates))
  assert.ok(baselinePost, 'Save persisted the baselineTemplates through /guard/api/prefs')
  assert.equal(baselinePost.baselineTemplates.length, 3, 'the whole baseline array is sent')
  const drifted = baselinePost.baselineTemplates.find((b) => b.id === 'intent-drift-detection')
  assert.equal(drifted.enabled, true, 'the toggled card backs on')
  assert.equal(drifted.prompt, 'INTENT drift prompt'.repeat(200), 'prompt text is unchanged (read-only)')
  // The other cards keep their enabled state + prompt.
  assert.equal(baselinePost.baselineTemplates.find((b) => b.id === 'malicious-intent-detection').enabled, true)
  assert.equal(baselinePost.baselineTemplates.find((b) => b.id === 'risk-instruction-detection').enabled, true)

  // ── Reload re-reads the server and discards the draft: the saved
  // enabled state wins again (the seeded GET returns the original table).
  const reloadBtn = find(renderPass(), 'dsg-action').filter((n) => n.children.join('') === 'Reload')[0]
  assert.ok(reloadBtn, 'the model tab carries a Reload button')
  reloadBtn.props.onClick()
  await flush()
  await flush()
  const reverted = baseCards().find((card) => cardLabel(card) === 'Intent Drift Detection')
  const revertedBox = collect(reverted, (n) => n && n.type === 'input' && n.props.type === 'checkbox')[0]
  assert.equal(revertedBox.props.checked, false, 'Reload restored the saved enabled state')
})

test('bundle: custom template hooks are multi-select chips over all 9 seams', async () => {
  const posts = []
  const runtime = makeRuntime()
  const baseFetch = runtime.fetch
  runtime.fetch = async (url, opts) => {
    const u = String(url)
    if (u.includes('/guard/api/prefs') && (!opts || opts.method !== 'POST')) {
      return { ok: true, json: async () => ({
        locale: 'auto', guardEnabled: true, rulesEnabled: true,
        modelReview: { enabled: true, mode: 'session', baselineTemplates: [], templates: [], baseUrl: '', apiKey: '', model: '', timeoutMs: 12000, protocol: 'openai-chat', thinking: 'default' },
      }) }
    }
    if (u.includes('/guard/api/prefs')) {
      posts.push(opts && opts.body ? JSON.parse(String(opts.body)) : null)
      return { ok: true, json: async () => ({ ok: true }) }
    }
    return baseFetch(url, opts)
  }
  const exportsObj = loadBundle(runtime)
  const { render: renderPass } = await mountModelTab(exportsObj, runtime)
  const find = (nodes, cls) => nodes.filter((n) => hasClass(n, cls))
  const flush = () => new Promise((resolve) => setTimeout(resolve, 0))

  // ── Custom template: the hook select is gone; the body carries a
  // multi-select chip row over the same 9-seam surface.
  // Click "+ Add template". NOTE: the test harness's collect() re-renders
  // function components during traversal, so the button's captured setState
  // closure can target a shifted state slot — the new template lands in the
  // store either way, and the card's own expand arrow (a plain UI affordance)
  // opens it deterministically. In the real React runtime the card simply
  // opens on add.
  const addBtn = collect(renderPass(), (n) => n && n.type === 'button' && n.children.join('') === '+ Add template')[0]
  assert.ok(addBtn, '+ Add template button present')
  addBtn.props.onClick()
  const tplCard = () => find(renderPass(), 'dsg-pcard').filter((c) => !String(c.props.className).includes('dsg-pcard-base'))[0]
  assert.ok(tplCard(), 'the new template card renders')
  const tplArrow = () => collect(tplCard(), (n) => n && n.props && (n.props.title === 'Expand' || n.props.title === 'Collapse'))[0]
  if (tplArrow() && tplArrow().props.title === 'Expand') tplArrow().props.onClick()
  const tplChips = () => collect(tplCard(), (n) => n && n.props
    && String(n.props.className || '').split(' ').includes('dsg-chip'))
  assert.equal(tplChips().length, 9, 'the template editor offers all 9 seams')
  // The card offers both affordances: 👁 View (read-only viewer) + ✎ Edit.
  const tplActions = collect(tplCard(), (n) => n && n.type === 'button'
    && (String(n.children.join('')).startsWith('\u{1F441} ') || String(n.children.join('')).startsWith('\u270e ')))
  assert.equal(tplActions.length, 2, 'the custom template card has both View and Edit affordances')
  const chipOn = (label) => {
    const c = tplChips().find((n) => n.children.join('') === label)
    return c && String(c.props.className).includes('dsg-chip-on')
  }
  assert.ok(chipOn('tools/pre-execute'), 'a new template defaults to the pre-execute seam')
  assert.ok(!chipOn('subagent/end'), 'other seams start off (multi-select, not radio)')

  // Multi-select: adding a seam KEEPS the first one; removing it leaves the
  // rest. Draft mode: the clicks stay local (no POST) until Save.
  const chipByLabel = (label) => tplChips().find((n) => n.children.join('') === label)
  chipByLabel('agent/pre-step').props.onClick()
  await flush()
  assert.ok(chipOn('tools/pre-execute') && chipOn('agent/pre-step'),
    'clicking a second hook ADDS it (multi-select, both lit)')
  const dirtyNodes = () => collect(renderPass(), (n) => n && n.props && String(n.props.className || '').split(' ').includes('dsg-dirty'))
  assert.ok(dirtyNodes().length > 0, 'the edited draft marks its inputs dirty (amber)')
  assert.equal(posts.length, 0, 'hook edits stay in the draft (no instant POST)')
  chipByLabel('tools/pre-execute').props.onClick()
  await flush()
  const saveBtn = find(renderPass(), 'dsg-action').filter((n) => n.children.join('') === 'Save')[0]
  assert.ok(saveBtn, 'the model tab carries a Save button')
  saveBtn.props.onClick()
  await flush()
  const tplPost = [...posts].reverse().map((p) => p && p.modelReview).find((mr) => mr && Array.isArray(mr.templates) && mr.templates.length > 0)
  assert.ok(tplPost, 'Save persisted the templates through /guard/api/prefs')
  assert.deepEqual(Array.from(tplPost.templates[0].hooks), ['agent/pre-step'],
    'the saved binding reflects both chip clicks (add then remove)')
  assert.equal(dirtyNodes().length, 0, 'after Save the dirty markers clear')

  // The execution-order field reflects the (single) chain position.
  const orderMeta = collect(tplCard(), (n) => n && n.props
    && String(n.props.className || '').includes('dsg-pcard-order'))[0]
  assert.ok(orderMeta, 'the order field renders')
  assert.ok(JSON.stringify(orderMeta).includes('agent/pre-step'), 'the order names the bound hook chain')

  // The filter row offers all + 9 seams, counting templates by inclusion.
  // (collect() flattens: the row's own children carry the chip array nested.)
  const filterRow = find(renderPass(), 'dsg-filters')[0]
  const filterChips = collect(filterRow, (n) => String(n.props?.className || '').split(' ').includes('dsg-filter'))
  assert.equal(filterChips.length, 10, 'all + 9 hook filters')
})

test('bundle: custom template disposition select narrows to allow/warn on observe-only bindings', async () => {
  const runtime = makeRuntime()
  const posts = []
  const baseFetch = runtime.fetch
  runtime.fetch = (url, opts) => {
    const u = typeof url === 'string' ? url : String(url)
    if (u.includes('/guard/api/prefs') && (!opts || opts.method !== 'POST')) {
      return { ok: true, json: async () => ({
        locale: 'auto', guardEnabled: true, rulesEnabled: true,
        modelReview: { enabled: true, mode: 'session', baselineTemplates: [], templates: [], baseUrl: '', apiKey: '', model: '', timeoutMs: 12000, protocol: 'openai-chat', thinking: 'default' },
      }) }
    }
    if (u.includes('/guard/api/prefs')) {
      posts.push(opts && opts.body ? JSON.parse(String(opts.body)) : null)
      return { ok: true, json: async () => ({ ok: true }) }
    }
    return baseFetch(url, opts)
  }
  const exportsObj = loadBundle(runtime)
  const { render: renderPass } = await mountModelTab(exportsObj, runtime)
  const find = (nodes, cls) => nodes.filter((n) => hasClass(n, cls))
  const flush = () => new Promise((resolve) => setTimeout(resolve, 0))

  // Create a template (lands bound to tools/pre-execute, cap = block) and
  // open its card if needed (same determinism note as the multi-select test).
  const addBtn = collect(renderPass(), (n) => n && n.type === 'button' && n.children.join('') === '+ Add template')[0]
  assert.ok(addBtn, '+ Add template button present')
  addBtn.props.onClick()
  const tplCard = () => find(renderPass(), 'dsg-pcard').filter((c) => !String(c.props.className).includes('dsg-pcard-base'))[0]
  const tplArrow = () => collect(tplCard(), (n) => n && n.props && (n.props.title === 'Expand' || n.props.title === 'Collapse'))[0]
  if (tplArrow() && tplArrow().props.title === 'Expand') tplArrow().props.onClick()
  const tplChips = () => collect(tplCard(), (n) => n && n.props
    && String(n.props.className || '').split(' ').includes('dsg-chip'))
  const capSelect = () => collect(tplCard(), (n) => n && n.type === 'select'
    && collect(n, (o) => o && o.props && ['allow', 'warn'].includes(o.props.value)).length >= 2)[0]
  const capOptions = () => collect(capSelect(), (o) => o && o.type === 'option'
    && typeof o.props?.value === 'string').map((o) => o.props.value)
  const chipByLabel = (label) => tplChips().find((n) => n.children.join('') === label)

  // 1. Fresh template (enforceable seam): full four-action surface, block cap.
  assert.deepEqual(capOptions(), ['allow', 'block', 'ask', 'warn'], 'enforceable binding offers all four actions')
  assert.equal(capSelect().props.value, 'block', 'a new template caps at block (= uncapped)')

  // 2. Mixed binding (one enforceable + one observe-only) keeps the full
  // surface — the enforceable seam can still interrupt.
  chipByLabel('tools/result').props.onClick()
  await flush()
  assert.deepEqual(capOptions(), ['allow', 'block', 'ask', 'warn'], 'mixed binding keeps all four actions')

  // 3. Removing the last enforceable seam → all-observe-only binding: the
  // select narrows to allow/warn and the block cap clamps down to warn.
  chipByLabel('tools/pre-execute').props.onClick()
  await flush()
  assert.deepEqual(capOptions(), ['allow', 'warn'], 'all-observe-only binding offers only allow/warn')
  assert.equal(capSelect().props.value, 'warn', 'the block cap displays clamped to warn')
  const capNote = collect(tplCard(), (n) => n && String(n.props?.className || '').split(' ').includes('dsg-note')
    && typeof n.props.children === 'string' && n.props.children.includes('the disposition narrows'))[0]
  assert.ok(capNote, 'the observe-only restriction renders an explanatory note')

  // 4. Saving persists the clamped cap through /guard/api/prefs.
  const saveBtn = find(renderPass(), 'dsg-action').filter((n) => n.children.join('') === 'Save')[0]
  assert.ok(saveBtn, 'the model tab carries a Save button')
  saveBtn.props.onClick()
  await flush()
  const tplPost = [...posts].reverse().map((p) => p && p.modelReview).find((mr) => mr && Array.isArray(mr.templates) && mr.templates.length > 0)
  assert.ok(tplPost, 'Save persisted the templates through /guard/api/prefs')
  assert.equal(tplPost.templates[0].action, 'warn', 'the clamped cap persists')
  assert.deepEqual(Array.from(tplPost.templates[0].hooks), ['tools/result'], 'the observe-only binding persists')
})
