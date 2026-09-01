/**
 * Built-in baseline threat policies (P0 + P1). Priority 50, below the user
 * default 100, so an explicit user policy always wins. `basePolicies: false`
 * in cordis.yml disables the whole table.
 *
 * Feature contract: the fields below are only present when a signal fired
 * (see `features.ts`), so each rule only fires on a real hit.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/base-policies
 */

import type { GuardPolicy } from './types.ts'

/** Baseline priority: user policies (default 100) take precedence. */
export const BASELINE_PRIORITY = 50

/** The built-in baseline policy table (27 policies). */
export function baselinePolicies(): readonly GuardPolicy[] {
  return [
    {
      id: 'base-block-high-risk-command',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'high-risk command blocked by security baseline (rm -rf /, pipe-to-shell, infinite loop, shutdown/format, shell rc truncation)',
      rules: [{ id: 'high-risk', field: 'highRisk', operator: 'eq', value: true }],
    },
    {
      id: 'base-block-obfuscated-command',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'obfuscated/encoded command delivery blocked by security baseline (base64|sh, xxd -r, hex escapes, invisible unicode)',
      rules: [{ id: 'obfuscated', field: 'obfuscated', operator: 'eq', value: true }],
    },
    {
      id: 'base-warn-overlong-command',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'unusually long command recorded in audit (harmless by itself; length alone never blocks)',
      rules: [{ id: 'overlong', field: 'overlong', operator: 'eq', value: true }],
    },
    {
      id: 'base-block-encoded-high-risk',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'encoded payload decoding to a high-risk or obfuscated command (base64/hex recursion) blocked by security baseline',
      rules: [{ id: 'encoded-high-risk', field: 'encodedHighRisk', operator: 'eq', value: true }],
    },
    {
      id: 'base-block-protected-path',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'access to protected path (~/.ssh, ~/.dsh, shell rc files, /etc sensitive files) blocked by security baseline',
      rules: [{ id: 'protected-path', field: 'protectedPathHit', operator: 'matches', value: '*' }],
    },
    {
      id: 'base-block-outside-delete',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'deletion outside the workspace blocked by security baseline',
      rules: [{ id: 'outside-delete', field: 'deleteOutsideWorkspace', operator: 'eq', value: true }],
    },
    {
      id: 'base-block-loop-hazard',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'same high-impact change repeated more than 3 times, possible tool loop, blocked by security baseline',
      rules: [{ id: 'loop', field: 'repeatExceeded', operator: 'eq', value: true }],
    },
    {
      id: 'base-block-artifact-execution',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'execution of a risky script written this turn blocked by security baseline',
      rules: [{ id: 'artifact-exec', field: 'artifactExecutionRisk', operator: 'eq', value: true }],
    },
    {
      id: 'base-block-exfil-chain',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'high-confidence data exfiltration chain blocked by security baseline',
      rules: [{ id: 'exfil-high', field: 'exfilChain', operator: 'eq', value: 'high' }],
    },
    {
      id: 'base-warn-exfil-chain',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'possible data exfiltration chain (outbound with secret reference or encoding transform), recorded in audit',
      rules: [{ id: 'exfil-medium', field: 'exfilChain', operator: 'eq', value: 'medium' }],
    },
    {
      id: 'base-block-tool-result-injection',
      hooks: ['tools/post-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'tool result contains a high-confidence (directive/encoded) prompt injection (persona hijack / safeguard defeat / tool luring / exfiltration instruction), blocked by security baseline',
      rules: [{ id: 'injection', field: 'toolResultRisk', operator: 'eq', value: 'block' }],
    },
    {
      id: 'base-warn-tool-result-injection',
      hooks: ['tools/post-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'tool result contains several soft injection phrases from unrelated families, recorded in audit',
      rules: [{ id: 'injection', field: 'toolResultRisk', operator: 'eq', value: 'warn' }],
    },
    {
      id: 'base-block-user-intent-attack',
      hooks: ['agent/pre-step'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'user message requests disabling the guard, bypassing approval, or ignoring restrictions; step rejected by security baseline',
      rules: [{ id: 'intent', field: 'userIntentRisk', operator: 'eq', value: 'block' }],
    },
    {
      id: 'base-warn-user-intent-attack',
      hooks: ['agent/pre-step'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'user message hints at bypassing restrictions; recorded in audit by security baseline',
      rules: [{ id: 'intent', field: 'userIntentRisk', operator: 'eq', value: 'warn' }],
    },
    // ---- operator_rules.yml merge (2026-08-31): execution-layer block tier ----
    {
      id: 'base-block-privilege-escalation',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'privilege escalation or security-control disable blocked by security baseline (setenforce 0, service stop/mask, chmod -R 777, chown root, setuid bit)',
      rules: [{ id: 'priv-esc', field: 'privEsc', operator: 'eq', value: 'block' }],
    },
    {
      id: 'base-warn-privilege-escalation',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'non-recursive world-writable chmod (chmod 777) recorded in audit by security baseline; single-file permission fixes may be legitimate',
      rules: [{ id: 'priv-esc-warn', field: 'privEsc', operator: 'eq', value: 'warn' }],
    },
    {
      id: 'base-block-system-path-write',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'write into system persistence locations (/etc cron|rc|profile|account files, Windows system dirs) blocked by security baseline',
      rules: [{ id: 'system-path-write', field: 'systemPathWrite', operator: 'eq', value: 'block' }],
    },
    {
      id: 'base-warn-system-path-write',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'install/copy into system bin or library dirs (/usr[/local]/bin, /Library) recorded in audit by security baseline; global CLI installs may be legitimate',
      rules: [{ id: 'system-path-write-warn', field: 'systemPathWrite', operator: 'eq', value: 'warn' }],
    },
    {
      id: 'base-block-config-tamper',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'in-place tampering with guard/policy files (sed -i / overwrite / delete on AGENTS.md, SKILL.md, policy configs) blocked by security baseline',
      rules: [{ id: 'config-tamper', field: 'configTamper', operator: 'eq', value: true }],
    },
    {
      id: 'base-block-sandbox-escape',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'block',
      message: 'sandbox/container escape tooling (nsenter, chroot execution, docker.sock mount, /proc/1/root, /:/ host mount) blocked by security baseline',
      rules: [{ id: 'sandbox-escape', field: 'sandboxEscape', operator: 'eq', value: 'block' }],
    },
    {
      id: 'base-warn-sandbox-escape',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'privileged container run (--privileged) recorded in audit by security baseline; testcontainers/DinD setups may be legitimate',
      rules: [{ id: 'sandbox-escape-warn', field: 'sandboxEscape', operator: 'eq', value: 'warn' }],
    },
    // ---- operator_rules.yml merge (2026-08-31): execution-layer warn tier ----
    {
      id: 'base-warn-net-recon',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'network scanning/listening (nmap, masscan, nc -l) recorded in audit by security baseline; may be legitimate debugging',
      rules: [{ id: 'net-recon', field: 'netRecon', operator: 'eq', value: true }],
    },
    {
      id: 'base-warn-path-traversal',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'multi-segment ../ path traversal in command recorded in audit by security baseline',
      rules: [{ id: 'path-traversal', field: 'pathTraversal', operator: 'eq', value: true }],
    },
    {
      id: 'base-warn-untrusted-source',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'clone-then-build/install chain from a freshly cloned source recorded in audit by security baseline',
      rules: [{ id: 'untrusted-source', field: 'untrustedSource', operator: 'eq', value: true }],
    },
    {
      id: 'base-warn-insecure-registry',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'package index/registry overridden to plain http:// recorded in audit by security baseline (supply-chain risk)',
      rules: [{ id: 'insecure-registry', field: 'insecureRegistry', operator: 'eq', value: true }],
    },
    {
      id: 'base-warn-secret-logging',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'code writing secret-looking values to logs (console.log/token|password|secret) recorded in audit by security baseline',
      rules: [{ id: 'secret-logging', field: 'secretLogging', operator: 'eq', value: true }],
    },
    {
      id: 'base-warn-memory-poison-write',
      hooks: ['tools/pre-execute'],
      priority: BASELINE_PRIORITY,
      action: 'warn',
      message: 'directive/trigger-phrase content written toward a memory-like target recorded in audit by security baseline (long-term memory poisoning risk)',
      rules: [{ id: 'memory-poison-write', field: 'memoryPoisonWrite', operator: 'eq', value: true }],
    },
  ]
}
