/**
 * Client half of the Security-Guard Review panel, a STATIC web plugin
 * (via the plugin's own in-process routes), replacing the old dynamic Cordis
 * runner
 * bundle (the `CLIENT_CODE` string that used to live in ui.ts).
 *
 * What changed vs. the dynamic version:
 *
 *   - transport: `host.call('guardX', ...)` → `fetch` against the plugin's
 *     own webServer routes (see api.ts / guard-api.ts). Wire protocol is
 *     identical, so all panel semantics carried over untouched;
 *   - timers: the static client runtime has no `timer` service (that was a
 *     cordis-client-runner mixin). The panel uses browser
 *     `setTimeout`/`setInterval` and returns disposers from effect cleanups;
 *   - CSS: `styles.insert(CSS)` (a runner-injected closure symbol) → a
 *     self-injected `<style data-plugin>` tag, removed on disposal;
 *   - no session anchoring: the header seat is session-scoped but the panel
 *     aggregates verdicts from ALL sessions (the host route already does the
 *     global fold), so no `agent.id`/sessionId is read anywhere.
 *
 * Unchanged: the module-scope store (open state + verdict rows + deny badge)
 * shared by every session-header seat, the 4s live poll while open, the
 * log/config tabs, and the `conversation.session.header.utilities` slot
 * registration.
 *
 * Added: a session-scoped `conversation.view` entry (`security-guard`) renders
 * the current session's verdict trail as a tab beside trajectory, and its
 * visibility is driven by the persisted `showSessionTab` preference. The
 * client apply registers/unregisters the entry live so toggling the setting
 * shows or hides the tab without a reload. The header shield button follows
 * the same pattern: the `conversation.session.header.utilities` seat is
 * present only while the persisted `showHeaderButton` preference is on. The
 * settings section (also in the DSH Settings shell) owns both toggles plus the
 * global protection master switch (`guardEnabled`), which the host engine
 * applies on the very next event.
 *
 * The bundle is a module-table consumer only: react is the single value
 * dependency (resolved by the loader table), everything else inlined.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/client
 */

import { createElement, useCallback, useEffect, useReducer, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { GuardClientContext, GuardSettingsSectionProps } from './types.ts'
import { canonicalGuardHook, guardApi, normalizeTemplateAction, OBSERVE_ONLY_HOOKS, POLICY_HOOKS, TEMPLATE_ACTIONS, templateHooksOf, type GuardLocale, type GuardVerdictRow, type ReviewTemplateLike, type TemplateAction, type TheGuardHook } from './api.ts'
import {
  attachLocale,
  effectiveLocale,
  fieldHint,
  getGuardEnabled,
  getModelReview,
  getPreference,
  getRecordAllow,
  getRulesEnabled,
  getShowHeader,
  getShowTab,
  modelReason,
  setGuardEnabled,
  setModelReview,
  setPreference,
  setRecordAllow,
  setRulesEnabled,
  setShowHeader,
  setShowTab,
  subscribeLocale,
  subscribePreference,
  t,
  templateName,
  verdictMessage,
} from './locales.ts'
import type { GuardCopyKey, ModelReviewPatch } from './locales.ts'

/** Service deps the bundle declares (slots + the DSH locale service). */
export const inject = ['slots', 'locale']

const CSS = [
  '.dsg-root{display:contents}',
  '.dsg-panel{position:fixed;top:56px;right:20px;left:auto;z-index:30;display:flex;flex-direction:column;width:min(560px,calc(100vw - 24px));max-width:calc(100vw - 24px);max-height:60vh;overflow:hidden;border:1px solid var(--dsw-alias-border-l1);border-radius:12px;background:var(--dsw-alias-bg-base);box-shadow:var(--dsw-shadow-lv2)}',
  '.dsg-header{flex:none;display:flex;align-items:center;justify-content:space-between;min-height:44px;padding:10px 12px;box-sizing:border-box;border-bottom:1px solid var(--dsw-alias-border-l2)}',
  '.dsg-title{font-size:13px;font-weight:500;line-height:20px;color:var(--dsw-alias-label-primary)}',
  '.dsg-body{flex:1;min-height:0;overflow-y:auto;overflow-x:hidden;padding:4px 12px 12px}',
  '.dsg-footer{flex:none;display:flex;flex-direction:column;gap:4px;padding:8px 12px 12px;box-sizing:border-box;border-top:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-base)}',
  '.dsg-summary{margin:4px 0 8px;font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}',
  '.dsg-note{margin:4px 0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}',
  '.dsg-error{margin:4px 0;font-size:12px;line-height:18px;color:var(--dsw-alias-state-error-primary)}',
  '.dsg-list{display:flex;flex-direction:column;gap:6px;margin:0;padding:0;list-style:none}',
  '.dsg-row{display:flex;flex-direction:column;gap:2px;padding:8px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:10px;background:var(--dsw-alias-bg-base);font-size:12px;line-height:18px}',
  '.dsg-row-head{display:flex;align-items:center;gap:8px;min-width:0}',
  '.dsg-badge{flex:none;display:inline-flex;align-items:center;height:18px;padding:0 6px;border-radius:9px;font-size:11px;line-height:18px}',
  '.dsg-badge-base{background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-tertiary)}',
  '.dsg-badge-custom{background:var(--dsw-alias-state-success-tertiary);color:var(--dsw-alias-state-success-primary)}',
  '.dsg-deny{background:var(--dsw-alias-interactive-bg-hover-danger);color:var(--dsw-alias-state-error-primary)}',
  '.dsg-ask{background:var(--dsw-alias-state-warn-tertiary);color:var(--dsw-alias-state-warn-label)}',
  '.dsg-warn{background:var(--dsw-alias-state-warn-tertiary);color:var(--dsw-alias-state-warn-label)}',
  '.dsg-pass{background:var(--dsw-alias-state-success-tertiary);color:var(--dsw-alias-state-success-primary)}',
  '.dsg-meta{flex:none;color:var(--dsw-alias-label-tertiary);font-size:11px}',
  '.dsg-msg{color:var(--dsw-alias-label-secondary);overflow-wrap:anywhere}',
  '.dsg-row{cursor:pointer}',
  '.dsg-row:hover{background:var(--dsw-alias-interactive-bg-hover)}',
  '.dsg-expand{flex:none;display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;padding:0;margin-left:auto;border:none;border-radius:5px;background:transparent;color:var(--dsw-alias-label-tertiary);font:inherit;font-size:11px;line-height:1;cursor:pointer}',
  '.dsg-expand:hover{background:var(--dsw-alias-interactive-bg-hover-solid);color:var(--dsw-alias-label-primary)}',
  '.dsg-expand-on{color:var(--dsw-alias-label-primary)}',
  '.dsg-detail{margin-top:6px;padding-top:6px;border-top:1px solid var(--dsw-alias-border-l2);min-width:0}',
  '.dsg-detail-meta{font-size:11px;line-height:16px;color:var(--dsw-alias-label-tertiary);overflow-wrap:anywhere}',
  '.dsg-detail-note{font-size:11px;line-height:16px;color:var(--dsw-alias-label-tertiary);font-style:italic}',
  '.dsg-detail-label{font-size:11px;line-height:16px;color:var(--dsw-alias-label-tertiary);margin:6px 0 2px}',
  '.dsg-detail-pre{margin:0;padding:6px 8px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-secondary);white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;max-height:320px;overflow-y:auto;font:11px/17px ui-monospace,SFMono-Regular,Menlo,monospace}',
  '.dsg-tabs{display:flex;gap:6px;margin:4px 0 8px}',
  '.dsg-tab{flex:none;padding:3px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:12px;cursor:pointer}',
  '.dsg-tab:hover{background:var(--dsw-alias-interactive-bg-hover)}',
  '.dsg-tab-active{background:var(--dsw-alias-interactive-bg-hover-solid);color:var(--dsw-alias-label-primary);border-color:var(--dsw-alias-border-l1)}',
  '.dsg-textarea{width:100%;min-height:170px;box-sizing:border-box;padding:8px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:11px/17px ui-monospace,SFMono-Regular,Menlo,monospace;resize:vertical}',
  // Compact read-only prompt preview inside template cards (the default
  // 170px editor height would drown the list).
  '.dsg-textarea.dsg-textarea-sm{min-height:64px}',
  // Read-only prompt preview: no caret / resize affordance, so the box does not
  // look like an editor now that the only write path is the Edit dialog.
  '.dsg-textarea[readonly]{cursor:default;background:var(--dsw-alias-bg-muted);resize:none}',
  '.dsg-textarea[readonly]:focus{outline:none}',
  '.dsg-actions{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0 4px}',
  '.dsg-action{padding:4px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:12px;cursor:pointer}',
  '.dsg-action:hover{background:var(--dsw-alias-interactive-bg-hover)}',
  '.dsg-action:disabled{opacity:.5;cursor:default}',
  '.dsg-action-danger:hover{background:var(--dsw-alias-interactive-bg-hover-danger);color:var(--dsw-alias-state-error-primary)}',
  '.dsg-ok{margin:4px 0;font-size:12px;line-height:18px;color:var(--dsw-alias-state-success-primary)}',
  '.dsg-src{margin:4px 0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}',
  '.dsg-count{position:absolute;top:-2px;right:-2px;flex:none;display:inline-flex;align-items:center;justify-content:center;min-width:16px;height:16px;padding:0 4px;border-radius:8px;background:var(--dsw-alias-interactive-bg-hover-danger);color:var(--dsw-alias-state-error-primary);font-size:10px;line-height:16px;font-weight:600}',
  '.dsg-hdr{position:relative;display:inline-flex;align-items:center;justify-content:center;gap:2px;min-width:28px;height:28px;padding:0 4px;border:none;border-radius:6px;background:transparent;color:var(--dsw-alias-label-tertiary);font-family:inherit;font-size:14px;line-height:1;cursor:pointer}',
  '.dsg-hdr:hover,.dsg-hdr:focus-visible{color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-interactive-bg-hover)}',
  '.dsg-hdr[aria-expanded="true"]{background:var(--dsw-alias-interactive-bg-hover-solid)}',
  // One uniform panel width for every tab (log / rules / model review) —
  // the shell no longer resizes when switching tabs.
  '.dsg-form{display:flex;flex-direction:column;gap:8px;margin:4px 0}',
  '.dsg-pcard{border:1px solid var(--dsw-alias-border-l2);border-radius:10px;background:var(--dsw-alias-bg-base);overflow:hidden}',
  '.dsg-pcard-order{display:flex;align-items:center;gap:6px}',
  '.dsg-pcard-order .dsg-meta{flex:1;white-space:pre-line}',
  '.dsg-pcard-base{border-color:var(--dsw-alias-border-l3)}',
  '.dsg-pcard-base .dsg-pcard-head{background:var(--dsw-alias-bg-muted)}',
  '.dsg-group-title{display:flex;align-items:center;gap:8px;margin:10px 0 6px;font-size:12px;line-height:20px;color:var(--dsw-alias-label-secondary)}',
  '.dsg-group-count{color:var(--dsw-alias-label-tertiary);font-size:11px}',
  '.dsg-group-toggle{flex:none;display:inline-flex;align-items:center;gap:4px;margin-left:auto;padding:2px 8px;border:1px solid var(--dsw-alias-border-l2);border-radius:6px;background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:11px;line-height:18px;cursor:pointer}',
  '.dsg-group-toggle:hover{background:var(--dsw-alias-interactive-bg-hover)}',
  '.dsg-pcard-head{display:flex;align-items:center;gap:6px;padding:6px 8px;box-sizing:border-box;border-bottom:1px solid var(--dsw-alias-border-l2)}',
  '.dsg-input{flex:1;min-width:0;padding:4px 8px;border:1px solid var(--dsw-alias-border-l2);border-radius:6px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:inherit;font-size:12px;box-sizing:border-box}',
  '.dsg-input:focus{outline:none;border-color:var(--dsw-alias-interactive-bg-hover-solid)}',
  // Unsaved-draft marker (model-review tab draft mode): amber border + tint
  // on any input/textarea whose value differs from the saved store.
  '.dsg-dirty{border-color:var(--dsw-alias-state-warn-label)!important;background:var(--dsw-alias-state-warn-tertiary)!important}',
  '.dsg-select{flex:1;min-width:0;padding:4px 6px;border:1px solid var(--dsw-alias-border-l2);border-radius:6px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:inherit;font-size:12px;box-sizing:border-box}',
  '.dsg-label{font-size:11px;line-height:16px;color:var(--dsw-alias-label-tertiary)}',
  '.dsg-chiprow{display:flex;flex-wrap:wrap;gap:4px}',
  '.dsg-chip{padding:2px 8px;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:11px;cursor:pointer}',
  '.dsg-chip:hover{background:var(--dsw-alias-interactive-bg-hover)}',
  '.dsg-chip-on{background:var(--dsw-alias-interactive-bg-hover-solid);color:var(--dsw-alias-label-primary);border-color:var(--dsw-alias-border-l1)}',
  '.dsg-chip:disabled{opacity:.4;cursor:not-allowed}',
  '.dsg-chip:disabled:hover{background:transparent}',
  '.dsg-rule{display:flex;align-items:center;gap:4px;width:100%}',
  '.dsg-fcell{flex:1;display:flex;align-items:center;gap:2px;min-width:0}',
  '.dsg-fcell .dsg-select{flex:1;min-width:0}',
  '.dsg-help{position:relative;flex:none;display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;margin-left:2px;border:1px solid var(--dsw-alias-border-l2);border-radius:50%;background:transparent;color:var(--dsw-alias-label-tertiary);font:inherit;font-size:10px;line-height:1;cursor:help}',
  '.dsg-help:hover{color:var(--dsw-alias-label-primary);border-color:var(--dsw-alias-border-l1)}',
  '.dsg-help:hover::after{content:attr(data-hint);position:absolute;z-index:120;top:calc(100% + 8px);left:0;max-width:min(280px, calc(100vw - 32px));padding:6px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:6px;background:var(--dsw-alias-bg-overlay);color:var(--dsw-alias-label-primary);font-size:11px;line-height:16px;font-weight:400;white-space:normal;overflow-wrap:anywhere;word-break:break-word;box-shadow:0 4px 16px rgb(0 0 0 / .18)}',
  // When the JS path renders the floating tip into document.body, hide the
  // in-card CSS ::after so they never stack.
  '.dsg-help.dsg-help-js:hover::after{display:none}',
  '.dsg-iconbtn{flex:none;display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;padding:0;border:none;border-radius:5px;background:transparent;color:var(--dsw-alias-label-tertiary);font:inherit;font-size:13px;line-height:1;cursor:pointer}',
  '.dsg-iconbtn:disabled{opacity:.4;cursor:default}',
  '.dsg-iconbtn:hover{background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-secondary)}',
  '.dsg-iconbtn-danger:hover{background:var(--dsw-alias-interactive-bg-hover-danger);color:var(--dsw-alias-state-error-primary)}',
  '.dsg-addbtn{align-self:flex-start;padding:2px 10px;border:1px dashed var(--dsw-alias-border-l2);border-radius:999px;background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:11px;cursor:pointer}',
  '.dsg-addbtn:hover{background:var(--dsw-alias-interactive-bg-hover)}',
  '.dsg-banner{margin:4px 0;padding:6px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-state-warn-tertiary);color:var(--dsw-alias-state-warn-label);font-size:12px;line-height:18px}',
  '.dsg-banner-danger{background:var(--dsw-alias-interactive-bg-hover-danger);color:var(--dsw-alias-state-error-primary)}',
  '.dsg-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px}',
  '.dsg-field{display:flex;flex-direction:column;gap:2px;min-width:0}',
  '.dsg-flabel{display:flex;align-items:center;gap:2px;min-width:0}',
  '.dsg-mono{font:11px/17px ui-monospace,SFMono-Regular,Menlo,monospace}',
  '.dsg-filters{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 8px}',
  // Static review chain (conversation-view Security Review tab): horizontal,
  // config-derived — one stage per native hook in lifecycle order.
  '.dsg-sc{margin:8px 0 12px;display:flex;align-items:flex-start;overflow-x:auto;padding-bottom:4px}',
  '.dsg-sc-title{font-size:12px;font-weight:600;color:var(--dsw-alias-label-primary);margin:8px 0 2px}',
  '.dsg-sc-stage{flex:none;display:flex;flex-direction:column;gap:5px;max-width:210px}',
  '.dsg-sc-node{align-self:flex-start;height:22px;display:inline-flex;align-items:center;padding:0 8px;border:1px solid var(--dsw-alias-border-l2);border-radius:6px;background:var(--dsw-alias-bg-muted);color:var(--dsw-alias-label-primary);font-size:11px;font-weight:600;white-space:nowrap}',
  '.dsg-sc-dim{opacity:.55}',
  '.dsg-sc-cards{display:flex;flex-direction:column;gap:4px}',
  '.dsg-sc-card{display:flex;flex-wrap:wrap;align-items:center;gap:3px;border:1px dashed var(--dsw-alias-border-l2);border-radius:6px;padding:4px 6px;max-width:210px}',
  '.dsg-sc-card-off{opacity:.45}',
  '.dsg-sc-card-h{flex-basis:100%;font-size:10px;color:var(--dsw-alias-label-secondary)}',
  '.dsg-sc-pol{display:inline-flex;align-items:center;max-width:190px;height:16px;padding:0 5px;border-radius:8px;background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-primary);font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
  '.dsg-sc-pol-custom{border:1px solid var(--dsw-alias-brand-primary);color:var(--dsw-alias-brand-primary);background:transparent}',
  '.dsg-sc-empty{font-size:10px;color:var(--dsw-alias-label-dimmed)}',
  '.dsg-sc-node,.dsg-sc-card,.dsg-sc-pol{transition:border-color .15s,background-color .15s,color .15s,box-shadow .15s}',
  '.dsg-sc-node:hover{border-color:var(--dsw-alias-brand-primary);color:var(--dsw-alias-brand-primary);background:var(--dsw-alias-interactive-bg-hover);box-shadow:0 0 0 1px var(--dsw-alias-brand-primary)}',
  '.dsg-sc-card:hover{border-color:var(--dsw-alias-brand-primary);border-style:solid;background:var(--dsw-alias-interactive-bg-hover)}',
  '.dsg-sc-pol:hover{border-color:var(--dsw-alias-brand-primary);color:var(--dsw-alias-brand-primary);background:var(--dsw-alias-bg-muted);box-shadow:0 0 0 1px var(--dsw-alias-brand-primary)}',
  '.dsg-sc-pol-custom:hover{background:var(--dsw-alias-brand-primary);color:var(--dsw-alias-bg-base)}',
  '.dsg-sc-link{flex:none;align-self:flex-start;margin-top:10px;width:20px;height:2px;background:var(--dsw-alias-border-l2);position:relative}',
  '.dsg-sc-link::after{content:\'\';position:absolute;right:-2px;top:-3px;border:4px solid transparent;border-left:5px solid var(--dsw-alias-border-l2)}',
  '.dsg-filter{flex:none;display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:12px;cursor:pointer}',
  '.dsg-filter:hover{background:var(--dsw-alias-interactive-bg-hover)}',
  '.dsg-fcount{flex:none;display:inline-flex;align-items:center;justify-content:center;height:16px;min-width:16px;padding:0 5px;border-radius:8px;font-size:10px;line-height:16px;background:var(--dsw-alias-interactive-bg-hover)}',
  '.dsg-filter-on{background:var(--dsw-alias-interactive-bg-hover-solid);color:var(--dsw-alias-label-primary);border-color:var(--dsw-alias-border-l1)}',
  '.dsg-filter-on .dsg-fcount{background:rgba(0,0,0,.15)}',
  '.dsg-filter-on-deny{background:var(--dsw-alias-interactive-bg-hover-danger);color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-border-l1)}',
  '.dsg-filter-on-deny .dsg-fcount{background:rgba(0,0,0,.12)}',
  '.dsg-filter-on-ask{background:var(--dsw-alias-state-warn-tertiary);color:var(--dsw-alias-state-warn-label);border-color:var(--dsw-alias-border-l1)}',
  '.dsg-filter-on-ask .dsg-fcount{background:rgba(0,0,0,.12)}',
  '.dsg-filter-on-warn{background:var(--dsw-alias-state-warn-tertiary);color:var(--dsw-alias-state-warn-label);border-color:var(--dsw-alias-border-l1)}',
  '.dsg-filter-on-warn .dsg-fcount{background:rgba(0,0,0,.12)}',
  '.dsg-filter-on-allow{background:var(--dsw-alias-state-success-tertiary);color:var(--dsw-alias-state-success-primary);border-color:var(--dsw-alias-border-l1)}',
  '.dsg-filter-on-allow .dsg-fcount{background:rgba(0,0,0,.12)}',
  // Settings-section language picker (rendered inside the DSH Settings shell).
  '.dsg-lang{display:flex;flex-direction:column;gap:12px;padding:4px 0;max-width:560px}',
  '.dsg-lang-row{display:flex;align-items:center;justify-content:space-between;gap:12px}',
  '.dsg-lang-col{display:flex;flex-direction:column;gap:2px;min-width:0}',
  // Constrain the label/description column inside input rows so the adjacent
  // input (e.g. custom review model address / name) keeps enough room instead
  // of being squeezed to a sliver by a long description that would otherwise
  // size the whole row.
  '.dsg-lang-row .dsg-lang-col{flex:0 0 200px;max-width:50%;overflow-wrap:anywhere}',
  // Let the field control take the rest of the row.
  '.dsg-lang-row .dsg-input,.dsg-lang-row .dsg-select,.dsg-lang-row textarea{flex:1;min-width:0}',
  '.dsg-lang-label{font-size:13px;line-height:20px;color:var(--dsw-alias-label-primary)}',
  '.dsg-lang-select{min-width:180px}',
  '.dsg-lang-intro{font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}',
  // Settings-section level-1 groups are collapsible cards (the plugin-config
  // gesture): a bordered container whose full-width header names the group,
  // rotates a chevron when open, and discloses the controls in place.
  '.dsg-card{border:1px solid var(--dsw-alias-border-l2);border-radius:10px;background:var(--dsw-alias-bg-layer-3);overflow:hidden}',
  '.dsg-card:hover{border-color:var(--dsw-alias-label-dimmed)}',
  '.dsg-card-open{background:var(--dsw-alias-bg-layer-2);border-color:var(--dsw-alias-label-dimmed)}',
  '.dsg-card-head{width:100%;box-sizing:border-box;display:flex;align-items:center;gap:10px;padding:10px 12px;border:none;background:none;font:inherit;color:inherit;text-align:left;cursor:pointer}',
  '.dsg-card-head:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:-2px}',
  '.dsg-card-text{flex:1;min-width:0;display:flex;flex-direction:column;gap:2px}',
  '.dsg-card-name{display:inline-flex;align-items:center;gap:4px;font-size:14px;font-weight:600;line-height:20px;color:var(--dsw-alias-label-primary)}',
  '.dsg-card-chev{flex:none;color:var(--dsw-alias-label-tertiary);transition:transform .16s}',
  '.dsg-card-open .dsg-card-chev{transform:rotate(180deg)}',
  '.dsg-card-body{border-top:1px solid var(--dsw-alias-border-l2);padding:10px 12px 12px;display:flex;flex-direction:column;gap:10px}',
  // Level-2 heading inside a card: deliberately smaller + tertiary so the
  // level-1 card header (14px/600) reads as the top of the hierarchy.
  '.dsg-sub-head{display:flex;align-items:center;gap:4px;margin:6px 0 -2px;font-size:12px;font-weight:500;color:var(--dsw-alias-label-tertiary)}',
  // Review-prompt editor: the first-level page shows a read-only preview with
  // a compact Edit trigger; the dialog it opens is a viewport-filling monospace
  // editor (the built-in audit template is 10k+ characters, unreadable in the
  // preview box). The dialog height must be *definite* top-down — a max-height
  // alone leaves the flex column content-sized, so the flexed textarea would
  // collapse to its intrinsic 2 rows. Hence: the fixed mask gives a definite
  // height, `height:100%` inherits it, and the textarea keeps a real `rows`
  // fallback for hosts that drop the percentage.
  '.dsg-prompt-head{display:flex;align-items:center;gap:6px;min-width:0}',
  '.dsg-modal-mask{position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;box-sizing:border-box;padding:clamp(8px,3vh,24px);background:rgb(0 0 0 / .45)}',
  '.dsg-modal{display:flex;flex-direction:column;width:min(960px,100%);height:100%;min-height:min(480px,100%);max-height:1100px;overflow:hidden;border:1px solid var(--dsw-alias-border-l1);border-radius:12px;background:var(--dsw-alias-bg-base);box-shadow:var(--dsw-shadow-lv2)}',
  '.dsg-modal-head{flex:none;display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 12px;border-bottom:1px solid var(--dsw-alias-border-l2)}',
  '.dsg-modal-title{font-size:13px;font-weight:600;line-height:20px;color:var(--dsw-alias-label-primary)}',
  '.dsg-modal-body{flex:1;min-height:0;display:flex;flex-direction:column;padding:10px 12px}',
  '.dsg-modal-textarea{flex:1;min-height:0;height:100%;width:100%;box-sizing:border-box;padding:10px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);font:12px/19px ui-monospace,SFMono-Regular,Menlo,monospace;resize:none}',
  '.dsg-modal-textarea:focus{outline:none;border-color:var(--dsw-alias-interactive-bg-hover-solid)}',
  '.dsg-modal-foot{flex:none;display:flex;align-items:center;gap:6px;padding:8px 12px;border-top:1px solid var(--dsw-alias-border-l2)}',
  '.dsg-modal-meta{flex:1;min-width:0;font-size:11px;line-height:16px;color:var(--dsw-alias-label-tertiary);overflow-wrap:anywhere}',
  // Conversation-view Security Review tab (rendered inside the session body).
  '.dsg-view{display:flex;flex-direction:column;gap:8px;padding:12px 16px;box-sizing:border-box;height:100%;overflow-y:auto;overflow-x:hidden}',
  '.dsg-check{flex:none;width:16px;height:16px;margin:0;accent-color:var(--dsw-alias-interactive-bg-hover-solid)}',
  // Review table: a scannable grid of verdicts (time / outcome / hook / tool /
  // message) with an expandable full-width detail row, in the style of the
  // harness trajectory view.
  '.dsg-table{width:100%;min-width:520px;border-spacing:0;table-layout:fixed;border:1px solid var(--dsw-alias-border-l2);border-radius:10px;overflow:hidden;background:var(--dsw-alias-bg-base)}',
  '.dsg-t-head th{position:sticky;top:0;z-index:3;box-sizing:border-box;height:30px;padding:0 10px;border-bottom:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-muted);color:var(--dsw-alias-label-tertiary);font-size:11px;line-height:30px;font-weight:500;text-align:left;user-select:none;white-space:nowrap}',
  '.dsg-t-head th.dsg-t-expand{width:36px}',
  '.dsg-table td{box-sizing:border-box;height:30px;padding:0 10px;overflow:hidden;border-bottom:1px solid var(--dsw-alias-border-l1);color:var(--dsw-alias-label-secondary);font-size:11px;line-height:30px;text-overflow:ellipsis;white-space:nowrap}',
  '.dsg-t-row{cursor:pointer}',
  '.dsg-t-row:hover td{background:var(--dsw-alias-interactive-bg-hover)}',
  '.dsg-t-outcome{width:76px}',
  '.dsg-t-type{width:56px}',
  '.dsg-t-hook{width:110px}',
  '.dsg-t-tool{width:120px}',
  '.dsg-t-time{width:88px;color:var(--dsw-alias-label-tertiary);font-variant-numeric:tabular-nums}',
  '.dsg-t-expand{width:36px;text-align:right}',
  '.dsg-t-msg{overflow:hidden}',
  '.dsg-t-msg-inner{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
  '.dsg-t-detail td{padding:8px 12px 10px;background:var(--dsw-alias-bg-layer-1);white-space:normal;overflow:visible;height:auto}',
  '.dsg-t-detail td:last-child{border-bottom:1px solid var(--dsw-alias-border-l2)}',
  '.dsg-t-detail .dsg-detail{margin-top:0;padding-top:0;border-top:none}',
  // Narrow widths: fall back to a per-row label grid so the table stays usable
  // inside a slim session pane.
  '@media (max-width:600px){.dsg-table thead{display:none}.dsg-t-row,.dsg-t-detail{display:block}.dsg-t-row td{display:flex;align-items:center;gap:8px;height:auto;min-height:28px;padding:2px 10px;border-bottom:none}.dsg-t-row td::before{content:attr(data-label);flex:none;width:64px;color:var(--dsw-alias-label-tertiary);font-size:11px}.dsg-t-outcome,.dsg-t-type,.dsg-t-hook,.dsg-t-tool,.dsg-t-msg{width:auto;white-space:normal;overflow:visible}.dsg-t-time{width:auto}.dsg-t-expand{display:none}.dsg-t-msg-inner{white-space:normal}.dsg-t-detail td{display:block;padding:8px 12px 10px;border-top:1px solid var(--dsw-alias-border-l1)}}',
  // Settings-nav icon (see settingsNavLabel): hide the host's fallback gear in
  // OUR nav row and show the shield that ships inside the section label. The
  // rule is scoped by :has(.dsg-nav-icon) so other plugin rows keep their
  // icons; engines without :has() render gear + shield (cosmetic only).
  '.dsg-nav-label{display:inline-flex;align-items:center;gap:6px;min-width:0}',
  '.dsg-nav-icon{flex:none}',
  'button[class*="navCell"]:has(.dsg-nav-icon)>svg:first-child{display:none}',
].join('\n')

/** Style-tag id (data-plugin marker; the loader removes plugin-owned tags on unload). */
const STYLE_TAG_ID = '@spark-shield-lab/deepseek-harness-security-guard/client'

/** Inject the panel CSS once; returns a disposer removing the tag. */
function injectStyle(): () => void {
  if (typeof document === 'undefined') return () => {}
  const existing = document.querySelector(`style[data-plugin="${STYLE_TAG_ID}"]`)
  if (existing !== null) return () => { existing.remove() }
  const tag = document.createElement('style')
  tag.dataset.plugin = STYLE_TAG_ID
  tag.textContent = CSS
  document.head.appendChild(tag)
  return () => { tag.remove() }
}

function outcomeLabel(r: { outcome?: string; modelStatus?: string }): string {
  if (r.modelStatus === 'error') return t('modelError')
  if (r.modelStatus === 'skipped') return t('modelSkipped')
  if (r.outcome === 'deny') return t('outcomeBlocked')
  if (r.outcome === 'ask') return t('outcomeAsk')
  if (r.outcome === 'warn') return t('outcomeWarned')
  return t('outcomeAllowed')
}

/** Badge class for a row's outcome cell (error/skipped rows use the neutral base). */
function outcomeBadgeClass(r: { outcome?: string; modelStatus?: string }): string {
  if (r.modelStatus === 'error') return 'dsg-badge-base'
  if (r.modelStatus === 'skipped') return 'dsg-badge-base'
  if (r.outcome === 'deny') return 'dsg-deny'
  if (r.outcome === 'ask') return 'dsg-ask'
  if (r.outcome === 'warn') return 'dsg-warn'
  return 'dsg-pass'
}

/** The review-chain type of a row: `Model` for model-review attempts, else `Rule`. */
function typeLabel(r: { kind?: string }): string {
  return r.kind === 'model' ? t('typeModel') : t('typeRule')
}

/** Render a review provider (host field → readable name). */
function providerName(p: { mode?: string; provider?: string; model?: string; baseUrl?: string }): string {
  if (p.mode === 'session') return [p.provider, p.model].filter((v) => typeof v === 'string' && v !== '').join('/')
  return [p.baseUrl, p.model].filter((v) => typeof v === 'string' && v !== '').join(' \u00b7 ')
}

function approvalLabel(outcome: string): string {
  if (outcome === 'allowed-once') return t('approvalAllowedOnce')
  if (outcome === 'rejected') return t('approvalRejected')
  if (outcome === 'cancelled') return t('approvalCancelled')
  if (outcome === 'unavailable') return t('approvalUnavailable')
  return outcome
}

/** A small badge showing the harness approval outcome on an ask verdict row. */
function approvalBadge(r: { approval?: string }): ReturnType<typeof createElement> | null {
  if (r.approval === undefined) return null
  const cls = r.approval === 'allowed-once' ? 'dsg-pass'
    : r.approval === 'rejected' ? 'dsg-deny'
      : 'dsg-badge-base'
  return createElement('span', {
    className: 'dsg-badge ' + cls,
    title: t('approvalTitle', { outcome: approvalLabel(r.approval) }),
  }, approvalLabel(r.approval))
}

/** A small badge marking an `ask` verdict that a hook WITHOUT an approval seam
 * degraded to a reject/block: the guard did not wait on a human, it refused.
 * Rendered beside the outcome label so "Awaiting confirmation" reads as what it actually was. */
function noSeamBadge(r: { noApprovalSeam?: boolean }): ReturnType<typeof createElement> | null {
  if (r.noApprovalSeam !== true) return null
  return createElement('span', {
    className: 'dsg-badge dsg-badge-base',
    title: t('noSeamTitle'),
  }, t('noSeamBadge'))
}

/** A small badge marking a post-hoc make-up review row (audit-only, non-enforcing):
 * the event was skipped on the first-request timing race and reviewed later. */
function makeupBadge(r: { modelLate?: boolean }): ReturnType<typeof createElement> | null {
  if (r.modelLate !== true) return null
  return createElement('span', {
    className: 'dsg-badge dsg-badge-base',
    title: t('makeupTitle'),
  }, t('makeupBadge'))
}

const LOG_FILTERS = ['all', 'deny', 'ask', 'warn', 'allow'] as const

function filterLabel(key: string): string {
  if (key === 'deny') return t('filterDeny')
  if (key === 'ask') return t('filterAsk')
  if (key === 'warn') return t('filterWarn')
  if (key === 'allow') return t('filterAllow')
  return t('filterAll')
}

function rowMatchesFilter(r: { outcome?: string }, key: string): boolean {
  if (key === 'deny') return r.outcome === 'deny'
  if (key === 'ask') return r.outcome === 'ask'
  if (key === 'warn') return r.outcome === 'warn'
  return r.outcome !== 'deny' && r.outcome !== 'ask' && r.outcome !== 'warn'
}

/* ---- structured Rule Config form helpers ---- */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyProps = Record<string, any>
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function el(type: any, props: AnyProps | null | undefined, ...children: unknown[]) {
  return createElement(type, props === undefined ? null : props, ...(children as ReactNode[]))
}

/**
 * Render a `?` help button whose hover tooltip shows `hint` in full.
 *
 * The CSS `::after` tooltip is only a fallback: the help button sits inside
 * `.dsg-pcard` (overflow:hidden), so a wide hint would be clipped by the
 * card edge. On hover we instead render the tip into `document.body` with
 * `position:fixed` (measured via getBoundingClientRect), which escapes every
 * overflow container and always shows the complete text. The JS path is
 * guarded so a minimal DOM (no body/rect) still falls back to the CSS tip.
 */
function helpButton(hint: string): ReturnType<typeof el> {
  return el('span', {
    className: 'dsg-help',
    'data-hint': hint,
    onMouseEnter: (e: { currentTarget: Element }) => showHelpTip(e.currentTarget, hint),
    onMouseLeave: hideHelpTip,
  }, '?')
}

/** Keep the single floating tip node (id `dsg-help-tip`) reused across fields. */
function showHelpTip(anchor: Element, text: string): void {
  if (typeof document === 'undefined' || !document.body || !anchor) return
  const elm = anchor as HTMLElement
  // DOM too minimal (test stubs) → keep the CSS ::after fallback.
  if (!elm.getBoundingClientRect || typeof document.getElementById !== 'function') return
  elm.classList.add('dsg-help-js')
  let tip = document.getElementById('dsg-help-tip')
  if (!tip) {
    tip = document.createElement('div')
    tip.id = 'dsg-help-tip'
    document.body.appendChild(tip)
  }
  tip.textContent = text
  tip.style.position = 'fixed'
  tip.style.zIndex = '10000'
  tip.style.maxWidth = 'min(320px, calc(100vw - 24px))'
  tip.style.padding = '6px 10px'
  tip.style.border = '1px solid var(--dsw-alias-border-l2)'
  tip.style.borderRadius = '6px'
  tip.style.background = 'var(--dsw-alias-bg-overlay)'
  tip.style.color = 'var(--dsw-alias-label-primary)'
  tip.style.fontSize = '11px'
  tip.style.lineHeight = '16px'
  tip.style.whiteSpace = 'normal'
  tip.style.overflowWrap = 'anywhere'
  tip.style.boxShadow = '0 4px 16px rgba(0,0,0,0.18)'
  const rect = elm.getBoundingClientRect()
  const viewW = typeof window !== 'undefined' && window.innerWidth ? window.innerWidth : 0
  const w = Math.min(320, Math.max(0, viewW - 24))
  tip.style.left = `${Math.max(8, Math.min(rect.left, Math.max(8, viewW - w - 8)))}px`
  tip.style.top = `${rect.bottom + 8}px`
  tip.style.display = 'block'
}

function hideHelpTip(): void {
  if (typeof document === 'undefined' || typeof document.getElementById !== 'function') return
  const tip = document.getElementById('dsg-help-tip')
  if (tip) tip.style.display = 'none'
}

/**
 * The panel enforces SINGLE-hook binding: a policy listens to exactly one hook
 * (no `*` all, no multi-select). `tools/pre-execute` is the default and the
 * ONLY hook with an approval seam. `ask` on any other hook degrades to
 * block/reject, so ask policies are locked to it.
 */
const DEFAULT_HOOK = 'tools/pre-execute'
const ASK_SAFE_HOOK = 'tools/pre-execute'
/**
 * Dropdown grouping for the rule field selector, mirroring the hook-surface
 * classification (universal / tool call / tool result / prompt). Groups render
 * as <optgroup> labels (localized at render time via the copy keys) so the
 * long field list stays scannable.
 */
const FIELD_GROUPS: ReadonlyArray<{ label: GuardCopyKey; fields: readonly string[] }> = [
  { label: 'groupUniversal', fields: ['eventType', 'agentId', 'agentType', 'sessionId', 'turn', 'step', 'raw'] },
  { label: 'groupToolCall', fields: ['toolName', 'arguments', 'command', 'highRisk', 'obfuscated', 'protectedPathHit', 'deleteOutsideWorkspace', 'outbound', 'secretRef', 'transformSignal', 'encodedHighRisk', 'scriptArtifactPath', 'scriptArtifactHash', 'scriptArtifactRisk', 'observedSecrets', 'repeatExceeded'] },
  { label: 'groupToolResult', fields: ['toolResultText', 'toolResultFlags', 'toolResultSuspicious', 'specialTokensRemoved', 'exfilChain', 'artifactExecutionRisk'] },
  { label: 'groupPromptContent', fields: ['content', 'userIntentRisk'] },
]

const FIELD_OPTIONS = ['eventType', 'agentId', 'agentType', 'content', 'sessionId', 'turn', 'step', 'raw', 'toolName', 'arguments', 'command', 'highRisk', 'obfuscated', 'protectedPathHit', 'deleteOutsideWorkspace', 'outbound', 'secretRef', 'transformSignal', 'encodedHighRisk', 'scriptArtifactPath', 'scriptArtifactHash', 'scriptArtifactRisk', 'repeatExceeded', 'exfilChain', 'artifactExecutionRisk', 'toolResultText', 'specialTokensRemoved', 'toolResultFlags', 'toolResultSuspicious', 'observedSecrets', 'userIntentRisk']
const VALUE_OPTIONS = ['true', 'false', 'high', 'medium', 'low', 'block', 'warn']

/**
 * Field-type metadata that drives the rule editor's typed controls.
 *
 * - `boolean`: the value becomes a true/false dropdown.
 * - `enum`: the value becomes a dropdown of known candidates (plus a custom
 *   entry), and the operator list is trimmed to eq/neq/in.
 * - `text`: free-form input (datalist suggestions still apply).
 *
 * Fields not listed here fall back to `text`, so the engine's dynamic
 * tool-argument fields (any primitive argument of a tool) stay editable.
 */
type FieldKind = 'boolean' | 'enum' | 'text'
interface FieldSchema {
  kind: FieldKind
  /** Candidate values for `enum` fields, in dropdown order. */
  values?: string[]
  /** Short hover hint shown on the field dropdown option. */
  hint?: string
  /**
   * Guard hooks this field is meaningful for. Omitted = universal (shown for
   * every hook, e.g. eventType/agentId). The rule editor hides fields whose
   * hook set does not intersect the policy's hooks, so e.g. `content` only
   * shows up when the policy listens to `agent/pre-step`.
   */
  hooks?: readonly string[]
}
// Tool-call hooks share the tool/argument surface; result hooks share the
// output surface; prompt hooks share the content surface. Fields with no
// `hooks` are universal (eventType, agentId, … and `raw`).
const HOOKS_TOOL: readonly string[] = ['tools/pre-execute', 'tools/result', 'tools/guard']
const HOOKS_RESULT: readonly string[] = ['tools/post-execute', 'tools/result']
const HOOKS_PROMPT: readonly string[] = ['agent/pre-step']
// Event-carried text exists on the prompt seam, at the stop boundary (the
// final assistant output) and on settled subagent runs (the child's output).
const HOOKS_CONTENT: readonly string[] = ['agent/pre-step', 'agent/turn-stopping', 'subagent/end']

const FIELD_SCHEMAS: Record<string, FieldSchema> = {
  // ── universal ──
  eventType: { kind: 'enum', values: POLICY_HOOKS, hint: fieldHint('hint_eventType', 'which guard hook produced the event') },
  agentId: { kind: 'text', hint: fieldHint('hint_agentId', 'the calling agent / session id') },
  agentType: { kind: 'enum', values: ['standard', 'code', 'research'], hint: fieldHint('hint_agentType', 'agent role (reserved)') },
  sessionId: { kind: 'text', hint: fieldHint('hint_sessionId', 'session id on the event') },
  turn: { kind: 'text', hint: fieldHint('hint_turn', 'turn number (integer)') },
  step: { kind: 'text', hint: fieldHint('hint_step', 'step number (integer)') },
  raw: {
    kind: 'text',
    hint: fieldHint('hint_raw', 'match against the full raw event payload as JSON, e.g. regex "\\\"command\\\": \\\"rm -rf\\\"" or contains "rm -rf"'),
  },

  // ── tool-call surface (tools/pre-execute / tools/result / tools/guard) ──
  toolName: {
    kind: 'enum',
    values: ['bash', 'sh', 'exec', 'run_code', 'ls', 'cat', 'rm', 'cp', 'mv', 'chmod', 'chown', 'sudo', 'curl', 'wget', 'git', 'npm', 'pip', 'python', 'node', 'docker', 'kubectl', 'sed', 'grep', 'find', 'ps', 'kill'],
    hint: fieldHint('hint_toolName', 'the tool the agent is about to call'),
    hooks: HOOKS_TOOL,
  },
  arguments: { kind: 'text', hint: fieldHint('hint_arguments', 'raw tool arguments as the harness passed them'), hooks: HOOKS_TOOL },
  command: {
    kind: 'enum',
    values: ['rm -rf', 'sudo rm -rf', 'chmod 777', 'chown -R', 'mkfs', 'dd if=', 'curl http://', 'wget http://', 'git clone', 'pip install', 'npm install', 'python -c'],
    hint: fieldHint('hint_command', 'substring of the command; matches supports * wildcards, e.g. ls* matches ls with any arguments'),
    hooks: HOOKS_TOOL,
  },
  highRisk: { kind: 'boolean', hint: fieldHint('hint_highRisk', 'heuristic high-risk call flag'), hooks: HOOKS_TOOL },
  obfuscated: { kind: 'boolean', hint: fieldHint('hint_obfuscated', 'obfuscated command / encoded payload'), hooks: HOOKS_TOOL },
  deleteOutsideWorkspace: { kind: 'boolean', hint: fieldHint('hint_deleteOutsideWorkspace', 'delete targets outside the workspace'), hooks: HOOKS_TOOL },
  outbound: { kind: 'boolean', hint: fieldHint('hint_outbound', 'network access beyond the sandbox'), hooks: HOOKS_TOOL },
  secretRef: { kind: 'boolean', hint: fieldHint('hint_secretRef', 'credentials referenced by the call'), hooks: HOOKS_TOOL },
  transformSignal: { kind: 'boolean', hint: fieldHint('hint_transformSignal', 'data-transformation heuristic fired'), hooks: HOOKS_TOOL },
  encodedHighRisk: { kind: 'boolean', hint: fieldHint('hint_encodedHighRisk', 'high-risk pattern present in encoded form'), hooks: HOOKS_TOOL },
  protectedPathHit: { kind: 'boolean', hint: fieldHint('hint_protectedPathHit', 'call touches a protected path'), hooks: HOOKS_TOOL },
  scriptArtifactPath: { kind: 'text', hint: fieldHint('hint_scriptArtifactPath', 'path of a generated script artifact'), hooks: HOOKS_TOOL },
  scriptArtifactHash: { kind: 'text', hint: fieldHint('hint_scriptArtifactHash', 'djb2 hash of a generated script artifact'), hooks: HOOKS_TOOL },
  scriptArtifactRisk: { kind: 'boolean', hint: fieldHint('hint_scriptArtifactRisk', 'generated artifact would execute code'), hooks: HOOKS_TOOL },
  observedSecrets: { kind: 'text', hint: fieldHint('hint_observedSecrets', 'secret-like values observed in the call'), hooks: HOOKS_TOOL },
  repeatExceeded: { kind: 'boolean', hint: fieldHint('hint_repeatExceeded', 'iteration budget exceeded'), hooks: HOOKS_TOOL },

  // ── result surface (tools/post-execute / tools/result) ──
  toolResultText: { kind: 'text', hint: fieldHint('hint_toolResultText', 'raw tool output text'), hooks: HOOKS_RESULT },
  toolResultFlags: { kind: 'text', hint: fieldHint('hint_toolResultFlags', 'tool result metadata flags'), hooks: HOOKS_RESULT },
  toolResultSuspicious: { kind: 'boolean', hint: fieldHint('hint_toolResultSuspicious', 'tool output looks like injected instructions'), hooks: HOOKS_RESULT },
  specialTokensRemoved: { kind: 'boolean', hint: fieldHint('hint_specialTokensRemoved', 'prompt-injection tokens stripped from the result'), hooks: HOOKS_RESULT },
  exfilChain: { kind: 'boolean', hint: fieldHint('hint_exfilChain', 'tool-result leakage chain detected'), hooks: HOOKS_RESULT },
  artifactExecutionRisk: { kind: 'boolean', hint: fieldHint('hint_artifactExecutionRisk', 'generated artifact would execute code'), hooks: HOOKS_RESULT },

  // ── prompt surface (agent/pre-step / agent/turn-stopping / subagent/end) ──
  content: { kind: 'text', hint: fieldHint('hint_content', 'text content the event carries (prompt text / final assistant output / subagent output)'), hooks: HOOKS_CONTENT },
  userIntentRisk: { kind: 'enum', values: ['high', 'medium', 'low'], hint: fieldHint('hint_userIntentRisk', 'model intent-risk classifier output'), hooks: HOOKS_PROMPT },
}

/**
 * Whether a field should appear in the rule editor for the given policy hooks.
 * Universal fields (no schema entry or no `hooks`) always show; scoped fields
 * show only when the policy hooks intersect theirs; `*` (all hooks) shows
 * everything.
 */
function fieldVisibleIn(policyHooks: string[], field: string): boolean {
  const hooks = (FIELD_SCHEMAS[field] || {}).hooks
  if (!hooks) return true
  if (policyHooks.length === 0) return true
  return policyHooks.some((h) => hooks.indexOf(h) !== -1)
}

/** Sentinel value that switches a typed dropdown into free-form editing. */
const CUSTOM_SENTINEL = '__custom__'
function fieldSchema(field: string): FieldSchema {
  return FIELD_SCHEMAS[field] || { kind: 'text' }
}

let uid = 1

function valueToText(v: unknown): string {
  if (v === undefined || v === null) return ''
  if (Array.isArray(v)) return v.join(', ')
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

function parseRuleValue(operator: string, text: unknown): unknown {
  const trimmed = String(text === undefined || text === null ? '' : text).trim()
  if (operator === 'in') {
    if (trimmed === '') return []
    if (trimmed[0] === '[') {
      const arr = JSON.parse(trimmed)
      if (!Array.isArray(arr)) throw new Error(t('errInArray'))
      return arr
    }
    return trimmed.split(',').map((s) => s.trim()).filter(Boolean)
  }
  if (trimmed === '') throw new Error(t('errValueEmpty'))
  if (trimmed === 'true') return true
  if (trimmed === 'false') return false
  if (trimmed === 'null') return null
  if (trimmed[0] === '[' || trimmed[0] === '{' || trimmed[0] === '"') return JSON.parse(trimmed)
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) return Number(trimmed)
  return trimmed
}

interface DraftRule {
  key: number
  field: string
  operator: string
  valueText: string
}

interface DraftPolicy {
  key: number
  id: string
  enabled: boolean
  priority: string
  action: string
  mode: string
  message: string
  hooks: string[]
  rules: DraftRule[]
  open: boolean
}

function newRule(): DraftRule {
  return { key: uid++, field: '', operator: 'eq', valueText: '' }
}

function newPolicy(): DraftPolicy {
  return { key: uid++, id: '', enabled: true, priority: '100', action: 'block', mode: '', message: '', hooks: [DEFAULT_HOOK], rules: [newRule()], open: true }
}

/**
 * Normalize any hook value to a SINGLE-element array (the panel contract).
 * `*` all, empty, or multi-select configs (legacy files, hand-edited) collapse
 * to the default hook; `ask` policies are pinned to `tools/pre-execute` because
 * it is the only hook with an approval seam (elsewhere ask degrades to
 * block/reject).
 */
function normalizeHooks(hooks: unknown, action?: string): string[] {
  let single: string
  if (!Array.isArray(hooks) || hooks.length === 0 || hooks.indexOf('*') !== -1) {
    single = DEFAULT_HOOK
  } else {
    // Canonicalize legacy v0.1.x hook names so hand-edited / old tables render
    // and save under native seam names.
    single = typeof hooks[0] === 'string' ? canonicalGuardHook(hooks[0]) : DEFAULT_HOOK
  }
  if (action === 'ask' && single !== ASK_SAFE_HOOK) single = ASK_SAFE_HOOK
  return [single]
}

/** Clamp a disposition onto an observe-only binding: nothing can interrupt
 * there, so block (and a stray ask) are dead weight. Clamps to `warn` (the
 * strictest record-only verdict) — deliberately NOT `ask`, which would
 * re-pin the binding to the approval seam and silently move the rule away
 * from the hook the user picked. */
function clampObserveOnlyAction(action: string, hooks: string[]): string {
  if (OBSERVE_ONLY_HOOKS.includes(hooks[0]!) && action !== 'allow' && action !== 'warn') return 'warn'
  return action
}

function policiesToDraft(policies: Array<Record<string, unknown>> | undefined): DraftPolicy[] {
  return (policies || []).map((p) => {
    const hooks = normalizeHooks(p.hooks, typeof p.action === 'string' ? p.action : undefined)
    const rawAction = typeof p.action === 'string' ? p.action : 'allow'
    return {
      key: uid++,
      id: typeof p.id === 'string' ? p.id : '',
      enabled: p.enabled !== false,
      priority: String(p.priority === undefined || p.priority === null ? 100 : p.priority),
      // Observe-only bindings can never interrupt the run, so a block (or a
      // stray ask) disposition from a hand-edited table clamps to warn (same
      // rule the editor's action select enforces).
      action: clampObserveOnlyAction(rawAction, hooks),
      mode: typeof p.mode === 'string' ? p.mode : '',
      message: typeof p.message === 'string' ? p.message : '',
      hooks,
      rules: Array.isArray(p.rules)
        ? (p.rules as Array<Record<string, unknown>>).map((r) => ({
            key: uid++,
            field: typeof r.field === 'string' ? r.field : '',
            operator: typeof r.operator === 'string' ? r.operator : 'eq',
            valueText: valueToText(r.value),
          }))
        : [],
      // All policy cards start collapsed; only the baseline GROUP is expanded
      // by default (the card bodies stay folded so the list stays compact).
      open: false,
    }
  })
}

function draftToPolicies(draft: DraftPolicy[]): Array<Record<string, unknown>> {
  return draft.map((p) => {
    const id = (p.id || '').trim()
    if (!id) throw new Error(t('errPolicyIdEmpty'))
    const priority = Number(p.priority)
    if (!Number.isFinite(priority)) throw new Error(t('errPolicyPriority', { id }))
    const rules = p.rules.map((r) => {
      const field = (r.field || '').trim()
      if (!field) throw new Error(t('errRuleFieldEmpty', { id }))
      return { field, operator: r.operator || 'eq', value: parseRuleValue(r.operator || 'eq', r.valueText) }
    })
    if (rules.length === 0) throw new Error(t('errPolicyNoRules', { id }))
    const hooks = normalizeHooks(p.hooks, p.action)
    const policy: Record<string, unknown> = { id, enabled: p.enabled, priority, hooks, action: clampObserveOnlyAction(p.action || 'allow', hooks), rules }
    const message = (p.message || '').trim()
    if (message) policy.message = message
    if (p.mode) policy.mode = p.mode
    return policy
  })
}

function validateDraft(draft: DraftPolicy[]): string | null {
  try {
    draftToPolicies(draft)
    return null
  } catch (e) {
    return e && typeof e === 'object' && 'message' in e ? String((e as { message: unknown }).message) : String(e)
  }
}

function patchPolicyIn(draft: DraftPolicy[], key: number, patch: Partial<DraftPolicy>): DraftPolicy[] {
  return draft.map((p) => (p.key === key ? { ...p, ...patch } : p))
}

/**
 * Built-in baseline policies are shipped from `src/base-policies.ts` and
 * always carry a `base-` id prefix. Everything else is user-authored
 * (cordis.yml / the config panel).
 */
function isBasePolicy(p: DraftPolicy): boolean {
  return (p.id || '').trim().startsWith('base-')
}

function removePolicyIn(draft: DraftPolicy[], key: number): DraftPolicy[] {
  return draft.filter((p) => p.key !== key)
}

interface GuardStore {
  open: boolean
  rows: GuardVerdictRow[]
  /** Incremental verdict cursor: only rows with seq > nextSeq are refetched (N9). */
  nextSeq: number
  loading: boolean
  error: string
  listeners: Set<() => void>
}

const store: GuardStore = {
  open: false,
  rows: [],
  nextSeq: 0,
  loading: false,
  error: '',
  listeners: new Set(),
}

// Browser timers only. The static client runtime has no `timer` service
// (that was a cordis-client-runner mixin).

/** One-shot delay; fire-and-forget. */
function once(cb: () => void, ms: number): void {
  setTimeout(cb, ms)
}

/** Repeated interval; returns a disposer the caller returns from a useEffect cleanup. */
function every(cb: () => void, ms: number): () => void {
  const id = setInterval(cb, ms)
  return () => { clearInterval(id) }
}

function emit(): void {
  const copy = [...store.listeners]
  for (const l of copy) l()
}

function patch(next: Partial<GuardStore>): void {
  Object.assign(store, next)
  emit()
}

function useGuardStore(): GuardStore {
  const [, force] = useReducer((x: number) => x + 1, 0)
  useEffect(() => {
    const listen = () => force()
    store.listeners.add(listen)
    return () => { store.listeners.delete(listen) }
  }, [])
  return store
}

/** Re-render the calling component whenever the panel language changes. */
function useLang(): void {
  const [, force] = useReducer((x: number) => x + 1, 0)
  useEffect(() => {
    const unsubPref = subscribePreference(force)
    const unsubLoc = subscribeLocale(force)
    return () => { unsubPref(); unsubLoc() }
  }, [])
}

/** Load the persisted preferences on boot; failures keep the schema defaults. */
async function loadPrefs(): Promise<void> {
  try {
    const res = await guardApi.getPrefs()
    if (res && res.locale) setPreference(res.locale)
    if (res && typeof res.showSessionTab === 'boolean') setShowTab(res.showSessionTab)
    if (res && typeof res.showHeaderButton === 'boolean') setShowHeader(res.showHeaderButton)
    if (res && typeof res.guardEnabled === 'boolean') setGuardEnabled(res.guardEnabled)
    if (res && typeof res.recordAllow === 'boolean') setRecordAllow(res.recordAllow)
    if (res && typeof res.rulesEnabled === 'boolean') setRulesEnabled(res.rulesEnabled)
    if (res && res.modelReview) {
      setModelReview(res.modelReview as ModelReviewPatch)
      mrMarkSaved()
    }
  } catch { /* keep the 'auto' locale and the visible defaults */ }
}

/** Apply a language preference locally and persist it through the settings route. */
async function persistLang(next: GuardLocale): Promise<void> {
  setPreference(next)
  try {
    await guardApi.setLang(next)
  } catch { /* keep the local choice on network failure */ }
}

/** Apply the tab-visibility preference locally and persist it through the settings route. */
async function persistShowTab(next: boolean): Promise<void> {
  setShowTab(next)
  try {
    await guardApi.setPrefs({ showSessionTab: next })
  } catch { /* keep the local choice on network failure */ }
}

/** Apply the header shield-button visibility and persist it through the settings route. */
async function persistShowHeader(next: boolean): Promise<void> {
  setShowHeader(next)
  try {
    await guardApi.setPrefs({ showHeaderButton: next })
  } catch { /* keep the local choice on network failure */ }
}

/** Apply the global protection master switch and persist it through the settings route. */
async function persistGuardEnabled(next: boolean): Promise<void> {
  setGuardEnabled(next)
  try {
    await guardApi.setPrefs({ guardEnabled: next })
  } catch { /* keep the local choice on network failure */ }
}

/** Apply the allow-recording preference and persist it through the settings route. */
async function persistRecordAllow(next: boolean): Promise<void> {
  setRecordAllow(next)
  try {
    await guardApi.setPrefs({ recordAllow: next })
  } catch { /* keep the local choice on network failure */ }
}

/** Apply the rule-stage switch and persist it through the settings route. */
async function persistRulesEnabled(next: boolean): Promise<void> {
  setRulesEnabled(next)
  try {
    await guardApi.setPrefs({ rulesEnabled: next })
  } catch { /* keep the local choice on network failure */ }
}

/** Apply a model-review patch locally (merged) and persist it through the settings route. */
async function persistModelReview(patch: ModelReviewPatch): Promise<void> {
  setModelReview(patch)
  try {
    // The settings fields persist instantly — but they must NOT carry the
    // Model Review tab's unsaved template draft along: send the last saved
    // template lists instead of the live store.
    await guardApi.setPrefs({
      modelReview: { ...getModelReview(), templates: mrSavedTemplates, baselineTemplates: mrSavedBaselines },
    })
  } catch { /* keep the local choice on network failure */ }
}

// ── Model-review draft bookkeeping (module scope, NOT React state). The
// store mirror carries the DRAFT: tab edits land there instantly and nothing
// is POSTed until Save; this snapshot remembers what the server last
// confirmed. `dirty` compares the two — module state instead of component
// state keeps the marker immune to the test harness's state-slot shifting
// (see tools/test-client-bundle.mjs) and mirrors the rule-config tab's
// save/reload semantics.
let mrSavedSig = '[[],[]]'
let mrSavedTemplates: ReviewTemplateLike[] = []
let mrSavedBaselines: ReviewTemplateLike[] = []

/** Normalize one template record for rendering/comparison (the legacy
 * v0.1.x single `hook` collapses into the `hooks` array; the disposition cap
 * drops unknown values and clamps to the binding — see
 * normalizeTemplateAction). */
function mrNormalizeTpl(tpl: ReviewTemplateLike): ReviewTemplateLike {
  const hooks = templateHooksOf(tpl)
  const action = normalizeTemplateAction(tpl.action, hooks)
  return {
    id: tpl.id,
    name: tpl.name,
    hooks,
    enabled: tpl.enabled,
    prompt: tpl.prompt,
    ...(action !== undefined ? { action } : {}),
  }
}

/** Refresh the saved snapshot from the store: called whenever the store
 * comes to reflect the SERVER (boot prefs load, Save success, Reload). */
function mrMarkSaved(): void {
  const mr = getModelReview()
  mrSavedTemplates = Array.isArray(mr.templates) ? mr.templates.map(mrNormalizeTpl) : []
  mrSavedBaselines = Array.isArray(mr.baselineTemplates) ? mr.baselineTemplates.map(mrNormalizeTpl) : []
  mrSavedSig = JSON.stringify([mrSavedBaselines, mrSavedTemplates])
}

// Model-tab footer UI state (module scope + a tiny subscription): busy/
// status/error live outside React so the pinned footer's buttons can call
// them without props drilling through GuardPanel, and stay immune to the
// test harness's state-slot shifting (same reasoning as the snapshot).
let mrBusy = false
let mrStatus = ''
let mrError = ''
const mrUiListeners = new Set<() => void>()

function setMrUi(patch: { busy?: boolean; status?: string; error?: string }): void {
  if (patch.busy !== undefined) mrBusy = patch.busy
  if (patch.status !== undefined) mrStatus = patch.status
  if (patch.error !== undefined) mrError = patch.error
  for (const listener of [...mrUiListeners]) listener()
}

/** Re-render the calling component when the model-tab footer state changes. */
function useMrUi(): void {
  const [, force] = useReducer((x: number) => x + 1, 0)
  useEffect(() => {
    mrUiListeners.add(force)
    return () => { mrUiListeners.delete(force) }
  }, [])
}

/** Whether the draft (store mirror) differs from the saved snapshot. */
function mrIsDirty(): boolean {
  const mr = getModelReview()
  const templates = Array.isArray(mr.templates) ? mr.templates.map(mrNormalizeTpl) : []
  const baselines = Array.isArray(mr.baselineTemplates) ? mr.baselineTemplates.map(mrNormalizeTpl) : []
  return JSON.stringify([baselines, templates]) !== mrSavedSig
}

/** Commit the draft (store mirror) through /guard/api/prefs; refreshes the
 * saved snapshot on success so the dirty banner and amber markers clear. */
async function mrSaveDraft(): Promise<void> {
  setMrUi({ busy: true, status: '', error: '' })
  try {
    // Normalized lists ride along (legacy `hook` collapses into `hooks`).
    const mr = getModelReview()
    const res = await guardApi.setPrefs({
      modelReview: {
        ...mr,
        templates: Array.isArray(mr.templates) ? mr.templates.map(mrNormalizeTpl) : [],
        baselineTemplates: Array.isArray(mr.baselineTemplates) ? mr.baselineTemplates.map(mrNormalizeTpl) : [],
      },
    })
    if (res && res.ok) {
      mrMarkSaved()
      setMrUi({ busy: false, status: res.message || t('saved') })
    } else {
      setMrUi({ busy: false, error: (res && res.error) || t('saveFailed') })
    }
  } catch (e) {
    setMrUi({ busy: false, error: e instanceof Error ? e.message : String(e) })
  }
}

/** Re-read the server into the store and drop the draft markers; the saved
 * snapshot moves with the server values so the tab renders clean. */
async function mrReloadDraft(): Promise<void> {
  setMrUi({ busy: true, status: '', error: '' })
  try {
    const res = await guardApi.getPrefs()
    if (res && res.modelReview) {
      setModelReview(res.modelReview as ModelReviewPatch)
      mrMarkSaved()
      setMrUi({ busy: false })
    } else {
      setMrUi({ busy: false, error: t('configReadFailed') })
    }
  } catch (e) {
    setMrUi({ busy: false, error: e instanceof Error ? e.message : String(e) })
  }
}

async function refreshVerdicts(silent?: boolean): Promise<void> {
  if (!silent) patch({ loading: true, error: '' })
  try {
    const after = store.nextSeq
    const result = await guardApi.verdicts(undefined, after)
    const fresh = Array.isArray(result) ? result : []
    if (fresh.length === 0) {
      if (!silent) patch({ loading: false })
      return
    }
    // Detect a truncation (audit file cleared / seq reset) and rebuild fully.
    const nonMonotonic = fresh.some((r) => r.seq <= store.nextSeq)
    let rows: GuardVerdictRow[]
    let nextSeq: number
    if (nonMonotonic) {
      rows = Array.isArray(result) ? result : []
      nextSeq = 0
      for (const r of rows) nextSeq = Math.max(nextSeq, r.seq)
    } else {
      const seen = new Map(store.rows.map((r) => [r.sessionId + ':' + String(r.seq), r]))
      for (const r of fresh) seen.set(r.sessionId + ':' + String(r.seq), r)
      rows = [...seen.values()].sort((a, b) => a.seq - b.seq)
      nextSeq = 0
      for (const r of fresh) nextSeq = Math.max(nextSeq, r.seq)
      nextSeq = Math.max(nextSeq, store.nextSeq)
    }
    patch({ rows, nextSeq })
  } catch (e) {
    if (!silent) patch({ error: e instanceof Error ? e.message : String(e) })
  } finally {
    if (!silent) patch({ loading: false })
  }
}

function togglePanel(): void {
  patch({ open: !store.open })
}

function GuardBadge({ deny }: { deny: number }): ReturnType<typeof createElement> | null {
  if (!deny) return null
  return createElement('span', {
    className: 'dsg-count',
    title: t('countBlocked', { n: String(deny) }),
  }, String(deny))
}

function RuleRow({ rule, onChange, onDelete, hooks, readOnly }: {
  rule: DraftRule
  onChange: (patch: Partial<DraftRule>) => void
  onDelete: () => void
  /** The owning policy's hook scope; drives which fields the dropdown offers. */
  hooks: string[]
  /** True = built-in baseline rule: every control renders inert (the layout
   * is unchanged, the row is display-only). */
  readOnly?: boolean
}): ReturnType<typeof createElement> {
  const locked = readOnly === true
  const field = rule.field.trim()
  const schema = fieldSchema(field)
  // A field is "known" when it ships in the built-in list. Those always
  // render as a dropdown. A known field whose hook scope doesn't cover the
  // policy's hooks (e.g. `content` while listening to tools/post-execute)
  // is still shown, pinned as an "out of scope" option, so the rule stays
  // visible and editable instead of degrading to a text box.
  const knownField = FIELD_OPTIONS.indexOf(field) !== -1
  const scopedOut = knownField && !fieldVisibleIn(hooks, field)
  const isKnownField = knownField || field === '' || field === CUSTOM_SENTINEL

  // Operator options trimmed to what makes sense for the field type. enum
  // fields (command/toolName) additionally get `matches` so glob patterns
  // like `ls*` or `write*` can be authored against the raw string value.
  const opOptions = schema.kind === 'boolean'
    ? ['eq', 'neq']
    : schema.kind === 'enum'
      ? ['eq', 'neq', 'in', 'matches', 'regex']
      : ['eq', 'neq', 'contains', 'in', 'matches', 'regex']

  // Field control: known fields become a grouped dropdown (Universal / Tool
  // call / Tool result / Prompt) with a hover help button; only genuinely
  // unknown/custom fields become a free-form input.
  let fieldControl: ReturnType<typeof el>
  if (isKnownField) {
    fieldControl = el('div', { className: 'dsg-fcell' },
      el('select', {
        className: 'dsg-select dsg-mono',
        value: field === CUSTOM_SENTINEL ? CUSTOM_SENTINEL : field,
        title: t('fieldSelectTitle'),
        disabled: locked,
        onChange: (e: { target: { value: string } }) => {
          const v = e.target.value
          // Picking a field changes its type, so reset operator/value; the
          // custom entry keeps the sentinel so the input below can edit it.
          onChange({ field: v, operator: 'eq', valueText: '' })
        },
      },
        el('option', { value: '' }, t('fieldPlaceholder')),
        // A field the current hook scope can't produce is pinned at the top
        // (labelled out of scope) instead of silently vanishing.
        scopedOut
          ? el('option', { value: field, title: t('outOfScope', { field }) }, t('outOfScope', { field }))
          : null,
        FIELD_GROUPS.map((g) => {
          const fields = g.fields.filter((f) => fieldVisibleIn(hooks, f))
          // Skip groups with no applicable fields for the current hook scope.
          if (fields.length === 0) return null
          return el('optgroup', { key: g.label, label: t(g.label) },
            fields.map((f) => el('option', {
              key: f,
              value: f,
              title: (FIELD_SCHEMAS[f] || {}).hint,
            }, f))
          )
        }),
        el('option', { value: CUSTOM_SENTINEL }, t('customOption'))
      ),
      helpButton((FIELD_SCHEMAS[field] || {}).hint
        || (field === '' ? t('fieldEmptyHint') : t('fieldCustomHint')))
    )
  } else {
    fieldControl = el('div', { className: 'dsg-fcell' },
      el('input', {
        className: 'dsg-input dsg-mono',
        value: rule.field,
        readOnly: locked,
        disabled: locked,
        onChange: (e: { target: { value: string } }) => onChange({ field: e.target.value }),
        placeholder: t('customFieldPlaceholder'),
        list: 'dsg-fields',
        spellCheck: false,
      }),
      helpButton(t('customFieldHint'))
    )
  }

  // Value control follows the field's type: boolean fields get a true/false
  // dropdown, enum fields get a candidate dropdown (with a custom entry),
  // everything else stays a free-form input.
  let valueControl: ReturnType<typeof el>
  if (schema.kind === 'boolean') {
    valueControl = el('select', {
      className: 'dsg-select dsg-mono',
      value: rule.valueText,
      disabled: locked,
      onChange: (e: { target: { value: string } }) => onChange({ valueText: e.target.value }),
    },
      el('option', { value: '' }, t('valuePlaceholder')),
      el('option', { value: 'true' }, 'true'),
      el('option', { value: 'false' }, 'false')
    )
  } else if (schema.kind === 'enum' && schema.values) {
    const candidates = schema.values
    if (candidates.indexOf(rule.valueText) !== -1 || rule.valueText === '') {
      valueControl = el('select', {
        className: 'dsg-select dsg-mono',
        value: rule.valueText,
        title: (schema.hint ? schema.hint + ' \u00b7 ' : '') + t('valueEnumHintSuffix'),
        disabled: locked,
        onChange: (e: { target: { value: string } }) => onChange({ valueText: e.target.value }),
      },
        el('option', { value: '' }, t('valuePlaceholder')),
        candidates.map((v) => el('option', { key: v, value: v }, v)),
        el('option', { value: CUSTOM_SENTINEL }, t('customOption'))
      )
    } else {
      valueControl = el('input', {
        className: 'dsg-input dsg-mono',
        value: rule.valueText,
        readOnly: locked,
        disabled: locked,
        onChange: (e: { target: { value: string } }) => onChange({ valueText: e.target.value }),
        placeholder: t('customValuePlaceholder'),
        list: 'dsg-values',
        spellCheck: false,
      })
    }
  } else {
    valueControl = el('input', {
      className: 'dsg-input dsg-mono',
      value: rule.valueText,
      readOnly: locked,
      disabled: locked,
      onChange: (e: { target: { value: string } }) => onChange({ valueText: e.target.value }),
      placeholder: rule.operator === 'in' ? t('valueInputHintIn') : rule.operator === 'matches' ? t('valueInputHintMatches') : t('valueInputHintText'),
      list: 'dsg-values',
      spellCheck: false,
    })
  }

  return el('div', { className: 'dsg-rule' },
    fieldControl,
    el('select', {
      className: 'dsg-select dsg-mono',
      value: opOptions.indexOf(rule.operator) !== -1 ? rule.operator : 'eq',
      disabled: locked,
      onChange: (e: { target: { value: string } }) => onChange({ operator: e.target.value }),
    },
      opOptions.map((o) => el('option', { key: o, value: o }, o))
    ),
    valueControl,
    // The ✕ stays in the row (layout unchanged) but is inert on a baseline rule.
    el('button', { type: 'button', className: 'dsg-iconbtn dsg-iconbtn-danger', title: t('removeRule'), onClick: onDelete, disabled: locked }, '\u2715')
  )
}

function PolicyEditor({ policy, onPatch, onDelete }: {
  policy: DraftPolicy
  onPatch: (key: number, patch: Partial<DraftPolicy>) => void
  onDelete: () => void
}): ReturnType<typeof createElement> {
  const set = (patch: Partial<DraftPolicy>) => onPatch(policy.key, patch)
  const setRule = (ruleKey: number, patch: Partial<DraftRule>) => set({ rules: policy.rules.map((r) => (r.key === ruleKey ? { ...r, ...patch } : r)) })
  const removeRule = (ruleKey: number) => set({ rules: policy.rules.filter((r) => r.key !== ruleKey) })
  const addRule = () => set({ rules: policy.rules.concat(newRule()) })
  // The editor always works off the normalized single hook (legacy `*`/multi
  // values collapse here too), so the chips and field scoping stay consistent
  // no matter how the draft was produced.
  const hooks = normalizeHooks(policy.hooks, policy.action)
  // Observe-only binding: the verdict can never interrupt the run there, so
  // the disposition narrows to allow/ask (block/warn would be dead weight).
  const observeOnlyHook = OBSERVE_ONLY_HOOKS.includes(hooks[0]!)
  const actionOptions: string[] = observeOnlyHook ? ['allow', 'warn'] : ['allow', 'block', 'ask', 'warn']
  const base = isBasePolicy(policy)

  const head = el('div', { className: 'dsg-pcard-head' },
    el('span', { className: 'dsg-badge ' + (base ? 'dsg-badge-base' : 'dsg-badge-custom') },
      base ? t('badgeBaseline') : t('badgeCustom')),
    el('input', {
      type: 'checkbox',
      checked: policy.enabled,
      title: t('enabledTitle'),
      onChange: (e: { target: { checked: boolean } }) => set({ enabled: e.target.checked }),
    }),
    el('input', {
      className: 'dsg-input',
      value: policy.id,
      placeholder: t('policyIdPlaceholder'),
      // Baseline cards are display-only: the id (like everything below) is
      // read-only, only the enabled checkbox stays live.
      readOnly: base,
      title: base ? t('baseMetaTitle') : undefined,
      onChange: (e: { target: { value: string } }) => set({ id: e.target.value }),
    }),
    el('select', {
      className: 'dsg-select',
      // An observe-only binding narrows the options; a loaded draft carrying
      // a now-unavailable action (e.g. hand-edited JSON) displays clamped.
      value: clampObserveOnlyAction(policy.action, hooks),
      title: observeOnlyHook ? t('hookObserveOnlyTitle') : undefined,
      disabled: base,
      // Switching to ask re-pins the hook to the approval seam immediately
      // (the draft otherwise keeps the raw hook until save).
      onChange: (e: { target: { value: string } }) => {
        const action = e.target.value
        set(action === 'ask' ? { action, hooks: [ASK_SAFE_HOOK] } : { action })
      },
    },
      actionOptions.map((a) => el('option', { key: a, value: a },
        a === 'allow' ? t('actionAllow')
          : a === 'block' ? t('actionBlock')
          : a === 'ask' ? t('actionAsk') : t('actionWarn')))
    ),
    el('button', {
      type: 'button',
      className: 'dsg-iconbtn',
      title: policy.open ? t('collapseTitle') : t('expandTitle'),
      onClick: () => set({ open: !policy.open }),
    }, policy.open ? '\u25be' : '\u25b8'),
    // Baseline policies are shipped from code and cannot be deleted. They can
    // only be disabled via the checkbox. Custom policies get the full delete.
    base
      ? el('span', { className: 'dsg-meta', title: t('baseMetaTitle') }, '\u26a0')
      : el('button', {
        type: 'button',
        className: 'dsg-iconbtn dsg-iconbtn-danger',
        title: t('deletePolicy'),
        onClick: onDelete,
      }, '\u2715')
  )

  const body: ReturnType<typeof el>[] = []
  if (policy.open) {
    // Per-hook affordance: ask locks to the approval seam; observe-only and
    // monotonic-guard hooks explain what a verdict does there.
    const hookHint = (h: string): string | undefined => {
      if (policy.action === 'ask' && h !== ASK_SAFE_HOOK) return t('hookLockedTitle')
      if (OBSERVE_ONLY_HOOKS.includes(h)) return t('hookObserveOnlyTitle')
      if (h === 'tools/guard') return t('hookGuardTitle')
      return undefined
    }
    body.push(el('div', { className: 'dsg-field' },
      el('span', { className: 'dsg-label' }, t('labelHooks')),
      el('div', { className: 'dsg-chiprow' },
        POLICY_HOOKS.map((h) =>
          el('button', {
            type: 'button',
            key: h,
            // Single-select: one chip on at a time. ask policies are locked to
            // tools/pre-execute (the only hook with an approval seam).
            className: 'dsg-chip' + (hooks[0] === h ? ' dsg-chip-on' : '') + (policy.action === 'ask' && h !== ASK_SAFE_HOOK ? ' dsg-chip-locked' : ''),
            title: hookHint(h),
            // Baseline hook binding is fixed — chips render inert, same layout.
            disabled: base || (policy.action === 'ask' && h !== ASK_SAFE_HOOK),
            onClick: () => set({
              hooks: [h],
              // Moving onto an observe-only seam clamps a block disposition
              // down to warn (the strictest record-only verdict): nothing can
              // interrupt there, and ask would re-pin the binding to the
              // approval seam. allow/warn stay as authored.
              ...(OBSERVE_ONLY_HOOKS.includes(h) && policy.action !== 'allow' && policy.action !== 'warn' ? { action: 'warn' } : {}),
            }),
          }, h)
        )
      ),
      policy.action === 'ask'
        ? el('div', { className: 'dsg-note' }, t('askHookNote'))
        : observeOnlyHook
          ? el('div', { className: 'dsg-note' }, t('dispositionObserveOnly'))
          : el('div', { className: 'dsg-note' }, t('hookNote'))
    ))
    body.push(el('div', { className: 'dsg-fields' },
      el('div', { className: 'dsg-field' },
        el('span', { className: 'dsg-label' }, t('labelPriority')),
        el('input', {
          className: 'dsg-input',
          type: 'number',
          value: policy.priority,
          readOnly: base,
          onChange: (e: { target: { value: string } }) => set({ priority: e.target.value }),
        })
      ),
      el('div', { className: 'dsg-field' },
        el('div', { className: 'dsg-flabel' },
          el('span', { className: 'dsg-label' }, t('labelMode')),
          helpButton(t('modeHint'))
        ),
        el('select', {
          className: 'dsg-select',
          value: policy.mode,
          disabled: base,
          onChange: (e: { target: { value: string } }) => set({ mode: e.target.value }),
        },
          el('option', { value: '' }, t('modeDefault')),
          el('option', { value: 'protect' }, t('modeProtect')),
          el('option', { value: 'monitor' }, t('modeMonitor'))
        )
      )
    ))
    body.push(el('div', { className: 'dsg-field' },
      el('span', { className: 'dsg-label' }, t('labelMessage')),
      el('input', {
        className: 'dsg-input',
        value: policy.message,
        placeholder: t('messagePlaceholder'),
        readOnly: base,
        onChange: (e: { target: { value: string } }) => set({ message: e.target.value }),
      })
    ))
    body.push(el('div', { className: 'dsg-field' },
      el('span', { className: 'dsg-label' }, t('labelRules')),
      el('div', { className: 'dsg-form' },
        policy.rules.map((r) =>
          el(RuleRow, {
            key: r.key,
            rule: r,
            hooks,
            readOnly: base,
            onChange: (patch: Partial<DraftRule>) => setRule(r.key, patch),
            onDelete: () => removeRule(r.key),
          })
        ),
        el('button', { type: 'button', className: 'dsg-addbtn', onClick: addRule, disabled: base }, t('addRule'))
      )
    ))
  }
  return el('div', { className: 'dsg-pcard' + (base ? ' dsg-pcard-base' : '') }, head, body)
}

function fmtTime(t: number | undefined): string {
  if (!t) return ''
  try {
    return new Date(t).toLocaleTimeString()
  } catch {
    return String(t)
  }
}

/**
 * Expanded detail body of one verdict row: durable meta plus the correlated
 * tool arguments / result text or prompt content served by the host half
 * (guardVerdicts attaches row.detail).
 */
function GuardDetail({ row }: { row: GuardVerdictRow }): ReturnType<typeof createElement> {
  const nodes: ReturnType<typeof el>[] = []
  const metaBits: string[] = []
  if (row.turn !== undefined) metaBits.push(t('metaTurn', { n: String(row.turn) }))
  if (row.step !== undefined) metaBits.push(t('metaStep', { n: String(row.step) }))
  if (row.callId) metaBits.push(t('metaCall', { id: row.callId }))
  if (row.policyId) metaBits.push(t('metaPolicy', { id: row.policyId }))
  if (row.source) metaBits.push(t('metaSource', { source: row.source }))
  if (row.modelVerdict?.action) metaBits.push(t('metaModelVerdict', { action: row.modelVerdict.action }))
  if (row.kind === 'model') {
    // Model-review attempt rows: show which model served the request and how
    // long the call took (a make-up review carries its own row-level badge).
    if (row.provider) metaBits.push(t('metaProvider', { name: providerName(row.provider) }))
    if (row.durationMs !== undefined) metaBits.push(t('metaDuration', { ms: String(row.durationMs) }))
  }
  if (row.approval !== undefined) metaBits.push(t('metaApproval', { outcome: approvalLabel(row.approval) }))
  const timeText = fmtTime(row.time)
  if (timeText) metaBits.push(timeText)
  if (metaBits.length > 0) nodes.push(el('div', { className: 'dsg-detail-meta' }, metaBits.join(' \u00b7 ')))
  const d = row.detail
  if (row.kind === 'model') {
    // The model-review procedure itself is the context here: failure detail,
    // skip reason, the rendered review prompt (request body) and the raw
    // output (response body).
    if (row.error) {
      nodes.push(el('div', { className: 'dsg-detail-label' }, t('labelError')))
      nodes.push(el('pre', { className: 'dsg-detail-pre' }, verdictMessage({ message: row.error })))
    }
    if (row.note) {
      nodes.push(el('div', { className: 'dsg-detail-label' }, t('labelNote')))
      nodes.push(el('pre', { className: 'dsg-detail-pre' }, verdictMessage({ message: row.note })))
    }
    if (row.request) {
      nodes.push(el('div', { className: 'dsg-detail-label' }, t('labelRequest')))
      nodes.push(el('pre', { className: 'dsg-detail-pre' }, row.request))
    }
    if (row.response) {
      nodes.push(el('div', { className: 'dsg-detail-label' }, t('labelResponse')))
      nodes.push(el('pre', { className: 'dsg-detail-pre' }, row.response))
    }
  } else if (!d || typeof d !== 'object') {
    nodes.push(el('div', { className: 'dsg-detail-note' }, t('noDetail')))
  } else if (d.kind === 'tool') {
    if (d.arguments !== undefined && d.arguments !== '') {
      nodes.push(el('div', { className: 'dsg-detail-label' }, t('labelArguments')))
      nodes.push(el('pre', { className: 'dsg-detail-pre' }, d.arguments))
    }
    if (d.result) {
      nodes.push(el('div', { className: 'dsg-detail-label' }, t('labelResult')))
      nodes.push(el('pre', { className: 'dsg-detail-pre' }, d.result))
    }
  } else if (d.kind === 'prompt' && d.content) {
    nodes.push(el('div', { className: 'dsg-detail-label' }, t('labelPrompt')))
    nodes.push(el('pre', { className: 'dsg-detail-pre' }, d.content))
  }
  if (row.modelVerdict?.reason) {
    nodes.push(el('div', { className: 'dsg-detail-label' }, t('metaModelReason')))
    nodes.push(el('pre', { className: 'dsg-detail-pre' }, modelReason(row.modelVerdict.reason)))
  }
  return el('div', { className: 'dsg-detail' }, nodes)
}

/** A verdict-row element builder shared by the header panel and the conversation view tab. */
function verdictRowElement(r: GuardVerdictRow, state: { key: string | number; isOpen: boolean; onToggle: () => void }): ReturnType<typeof createElement> {
  const head: ReturnType<typeof createElement>[] = []
  head.push(createElement('span', {
    className: 'dsg-badge ' + outcomeBadgeClass(r),
  }, outcomeLabel(r)))
  const approval = approvalBadge(r)
  if (approval !== null) head.push(approval)
  const noSeam = noSeamBadge(r)
  if (noSeam !== null) head.push(noSeam)
  const makeup = makeupBadge(r)
  if (makeup !== null) head.push(makeup)
  if (r.hook) head.push(createElement('span', { className: 'dsg-meta' }, r.hook))
  if (r.tool) head.push(createElement('span', { className: 'dsg-meta' }, r.tool))
  head.push(createElement('button', {
    type: 'button',
    className: 'dsg-expand' + (state.isOpen ? ' dsg-expand-on' : ''),
    title: state.isOpen ? t('hideDetails') : t('showDetails'),
    'aria-label': state.isOpen ? t('hideDetailsAria') : t('showDetailsAria'),
    'aria-expanded': state.isOpen,
    onClick: (e: { stopPropagation(): void }) => { e.stopPropagation(); state.onToggle() },
  }, state.isOpen ? '\u25be' : '\u25b8'))
  const detail: ReturnType<typeof createElement>[] = []
  if (r.message) detail.push(createElement('div', { className: 'dsg-msg' }, verdictMessage(r)))
  if (state.isOpen) detail.push(createElement(GuardDetail, { row: r }))
  return createElement('li', { key: state.key, className: 'dsg-row', onClick: state.onToggle, title: t('rowTitle') },
    createElement('div', { className: 'dsg-row-head' }, head),
    detail
  )
}

/**
 * Build one body row (barring the expandable detail row) of the review table.
 * Rendered for the conversation-view Security Review tab so verdicts read as
 * a scannable grid (time / outcome / hook / tool / message) instead of stacked
 * cards.
 */
function verdictTableRow(r: GuardVerdictRow, state: { key: string | number; isOpen: boolean; onToggle: () => void }): ReturnType<typeof createElement> {
  const tds: ReturnType<typeof createElement>[] = []
  tds.push(createElement('td', { className: 'dsg-t-time', 'data-label': t('thTime') }, fmtTime(r.time)))
  const outcomeCells: ReturnType<typeof createElement>[] = [createElement('span', {
    className: 'dsg-badge ' + outcomeBadgeClass(r),
  }, outcomeLabel(r))]
  const approval = approvalBadge(r)
  if (approval !== null) outcomeCells.push(approval)
  const noSeam = noSeamBadge(r)
  if (noSeam !== null) outcomeCells.push(noSeam)
  const makeupCell = makeupBadge(r)
  if (makeupCell !== null) outcomeCells.push(makeupCell)
  tds.push(createElement('td', { className: 'dsg-t-outcome', 'data-label': t('thOutcome') }, outcomeCells))
  tds.push(createElement('td', { className: 'dsg-t-type', 'data-label': t('thType') }, typeLabel(r)))
  tds.push(createElement('td', { className: 'dsg-t-hook', 'data-label': t('thHook') }, r.hook ?? ''))
  tds.push(createElement('td', { className: 'dsg-t-tool', 'data-label': t('thTool') }, r.tool ?? ''))
  tds.push(createElement('td', { className: 'dsg-t-msg', 'data-label': t('thMessage') },
    createElement('span', { className: 'dsg-t-msg-inner', title: verdictMessage(r) }, verdictMessage(r))
  ))
  tds.push(createElement('td', { className: 'dsg-t-expand' },
    createElement('button', {
      type: 'button',
      className: 'dsg-expand' + (state.isOpen ? ' dsg-expand-on' : ''),
      title: state.isOpen ? t('hideDetails') : t('showDetails'),
      'aria-label': state.isOpen ? t('hideDetailsAria') : t('showDetailsAria'),
      'aria-expanded': state.isOpen,
      onClick: (e: { stopPropagation(): void }) => { e.stopPropagation(); state.onToggle() },
    }, state.isOpen ? '\u25be' : '\u25b8')
  ))
  return createElement('tr', { key: state.key, className: 'dsg-t-row', onClick: state.onToggle, title: t('rowTitle') }, tds)
}

/**
 * The expandable detail row of the review table: a full-width cell holding
 * the same GuardDetail body the header panel shows, so an expanded verdict's
 * context never hides behind the column grid.
 */
function verdictTableDetailRow(r: GuardVerdictRow, key: string | number): ReturnType<typeof createElement> {
  return createElement('tr', { key, className: 'dsg-t-detail' },
    createElement('td', { colSpan: 7 }, createElement(GuardDetail, { row: r }))
  )
}

function GuardPanel(): ReturnType<typeof createElement> {
  const [tab, setTab] = useState<'log' | 'config' | 'model'>('log')
  const [eff, setEff] = useState<{ source?: string; version?: number; policies?: Array<Record<string, unknown>>; error?: string } | null>(null)
  const [draft, setDraft] = useState<DraftPolicy[]>([])
  const [rawOpen, setRawOpen] = useState(false)
  const [rawText, setRawText] = useState('')
  const [cfgStatus, setCfgStatus] = useState('')
  const [cfgError, setCfgError] = useState('')
  const [busy, setBusy] = useState(false)
  const [logFilter, setLogFilter] = useState('all')
  const [logNote, setLogNote] = useState('')
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  // The built-in baseline policies group starts EXPANDED so the shipped
  // baseline is visible without an extra click; users can still collapse it.
  const [baseOpen, setBaseOpen] = useState(true)
  // Hook filter for the config tab's policy list (mirrors the model-review
  // tab's chips): 'all' or one native hook name. Policies bind exactly one
  // hook (the panel contract), so the filter is a simple inclusion check.
  const [hookFilter, setHookFilter] = useState<'all' | string>('all')
  const { open, rows, loading, error } = useGuardStore()
  // Keep the panel's own hooks last (after the state the tests drive by index);
  // this subscribes the render loop to language-preference / DSH-locale changes.
  useLang()

  // Clicking anywhere outside the shield button + panel closes the panel.
  // pointerdown wins over the header toggle on the same gesture, so a click on
  // the button still toggles (its target sits inside .dsg-root and is skipped),
  // while a click anywhere else auto-hides the open menu.
  useEffect(() => {
    if (!open || typeof document === 'undefined') return undefined
    const onPointerDown = (e: Event) => {
      const target = e.target
      if (!target || typeof (target as Element).closest !== 'function') return
      if ((target as Element).closest('.dsg-root') !== null) return
      patch({ open: false })
    }
    document.addEventListener('pointerdown', onPointerDown)
    return () => document.removeEventListener('pointerdown', onPointerDown)
  }, [open])

  const refresh = useCallback(() => { void refreshVerdicts() }, [])

  const clearLog = useCallback(async () => {
    try {
      const res = await guardApi.clearVerdicts()
      store.nextSeq = 0
      patch({ rows: [] })
      setLogNote((res && res.message) || t('clearNote'))
    } catch (e) {
      setLogNote(t('clearFailed') + (e instanceof Error ? e.message : String(e)))
    }
    once(() => setLogNote(''), 5000)
    void refreshVerdicts()
  }, [])

  useEffect(() => {
    if (open) { void refreshVerdicts() } else { void refreshVerdicts(true) }
    if (!open) return undefined
    const dispose = every(() => { void refreshVerdicts(true) }, 4000)
    return () => { dispose() }
  }, [open, refresh])

  const loadEffective = useCallback(async () => {
    setCfgError('')
    try {
      const res = await guardApi.getPolicies()
      if (res && res.ok) {
        setEff(res.data || null)
        setDraft(policiesToDraft((res.data && res.data.policies) || []))
        setCfgStatus('')
      } else {
        setEff(null)
        setCfgError((res && res.error) || t('configReadFailed'))
      }
    } catch (e) {
      setEff(null)
      setCfgError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    if (open && tab === 'config') { void loadEffective() }
  }, [open, tab, loadEffective])

  const savePolicies = useCallback(async () => {
    setBusy(true)
    setCfgError('')
    setCfgStatus('')
    try {
      const problem = validateDraft(draft)
      if (problem) { setCfgError(problem); return }
      const table = { v: 1, policies: draftToPolicies(draft) }
      const res = await guardApi.savePolicies(table)
      if (res && res.ok) {
        setCfgStatus(res.message || t('saved'))
        once(() => { void loadEffective() }, 1200)
      } else {
        setCfgError((res && res.error) || t('saveFailed'))
      }
    } catch (e) {
      setCfgError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }, [draft, loadEffective])

  const addPolicy = useCallback(() => {
    setCfgError('')
    // New policies land at the top of the list so the newest is the easiest
    // to see and edit. Under an active hook filter the new policy binds THAT
    // hook, so it is immediately visible instead of hiding behind the filter.
    const p = newPolicy()
    if (hookFilter !== 'all') p.hooks = [hookFilter]
    setDraft((d) => [p, ...d])
  }, [hookFilter])

  const openRaw = useCallback(() => {
    setCfgError('')
    try {
      setRawText(JSON.stringify({ v: 1, policies: draftToPolicies(draft) }, null, 2))
    } catch {
      setRawText(JSON.stringify({ v: 1, policies: [] }, null, 2))
    }
    setRawOpen(true)
  }, [draft])

  const applyRaw = useCallback(() => {
    setCfgError('')
    try {
      const parsed: unknown = JSON.parse(rawText)
      let policies: Array<Record<string, unknown>>
      if (Array.isArray(parsed)) {
        policies = parsed as Array<Record<string, unknown>>
      } else {
        if (!parsed || typeof parsed !== 'object' || !Array.isArray((parsed as { policies?: unknown }).policies)) {
          throw new Error(t('errJsonShape'))
        }
        policies = (parsed as { policies: Array<Record<string, unknown>> }).policies
      }
      const next = policiesToDraft(policies)
      const problem = validateDraft(next)
      if (problem) throw new Error(problem)
      setDraft(next)
      setRawOpen(false)
    } catch (e) {
      setCfgError(t('jsonApplyFailed') + (e instanceof Error ? e.message : String(e)))
    }
  }, [rawText])

  let pass = 0
  let deny = 0
  let ask = 0
  let warn = 0
  for (const r of rows) {
    if (r.outcome === 'deny') deny += 1
    else if (r.outcome === 'ask') ask += 1
    else if (r.outcome === 'warn') warn += 1
    else pass += 1
  }

  const children: ReturnType<typeof createElement>[] = []
  children.push(createElement('button', {
    type: 'button',
    className: 'dsg-hdr',
    title: t('headerButton'),
    'aria-label': t('panelTitle'),
    'aria-expanded': open,
    onClick: togglePanel,
  },
    shieldIcon('dsg-hdr-icon', 14),
    createElement(GuardBadge, { deny })
  ))

  if (open) {
    const bodyChildren: ReturnType<typeof createElement>[] = []
    // Config-tab footer: save/reload + status/error stay pinned to the bottom
    // of the panel, always visible even when the rule list scrolls.
    const footerChildren: ReturnType<typeof createElement>[] = []
    bodyChildren.push(createElement('div', { className: 'dsg-summary' },
      t('summary', { deny, ask, warn, pass })
    ))
    bodyChildren.push(createElement('div', { className: 'dsg-tabs' },
      createElement('button', {
        type: 'button',
        className: 'dsg-tab' + (tab === 'log' ? ' dsg-tab-active' : ''),
        onClick: () => setTab('log'),
      }, t('tabLog')),
      createElement('button', {
        type: 'button',
        className: 'dsg-tab' + (tab === 'config' ? ' dsg-tab-active' : ''),
        onClick: () => setTab('config'),
      }, t('tabConfig')),
      createElement('button', {
        type: 'button',
        className: 'dsg-tab' + (tab === 'model' ? ' dsg-tab-active' : ''),
        onClick: () => setTab('model'),
      }, t('tabModelReview'))
    ))
    if (tab === 'log') {
      bodyChildren.push(createElement('div', { className: 'dsg-filters' },
        LOG_FILTERS.map((key) => {
          let count: number
          if (key === 'all') count = rows.length
          else if (key === 'deny') count = deny
          else if (key === 'ask') count = ask
          else if (key === 'warn') count = warn
          else count = pass
          let cls = 'dsg-filter'
          if (logFilter === key) {
            cls += ' dsg-filter-on' + (key === 'all' ? '' : '-' + key)
          }
          return createElement('button', {
            type: 'button',
            key: key,
            className: cls,
            title: t('filterTitle', { label: filterLabel(key) }),
            onClick: () => setLogFilter(key),
          },
            createElement('span', null, filterLabel(key)),
            createElement('span', { className: 'dsg-fcount' }, String(count))
          )
        })
      ))
      bodyChildren.push(createElement('div', { className: 'dsg-actions' },
        createElement('button', {
          type: 'button',
          className: 'dsg-action',
          onClick: refresh,
          disabled: loading,
        }, loading ? t('loading') : t('refresh')),
        createElement('button', {
          type: 'button',
          className: 'dsg-action dsg-action-danger',
          onClick: clearLog,
          title: t('clearLogTitle'),
        }, t('clearLog'))
      ))
      if (error) bodyChildren.push(createElement('div', { className: 'dsg-error' }, error))
      if (logNote) bodyChildren.push(createElement('div', { className: 'dsg-ok' }, logNote))
      if (rows.length === 0 && !loading && !error) {
        bodyChildren.push(createElement('div', { className: 'dsg-note' }, t('noVerdicts')))
      }
      let listRows = rows
      if (logFilter !== 'all') {
        listRows = listRows.filter((r) => rowMatchesFilter(r, logFilter))
        if (rows.length > 0 && listRows.length === 0) {
          bodyChildren.push(createElement('div', { className: 'dsg-note' },
            t('noFilterWindow', { label: filterLabel(logFilter) })))
        }
      }
      const rowElements = listRows.slice(0, 200).map((r, i) => {
        const key = r.sessionId + ':' + String(r.seq)
        const isOpen = expanded[key] === true
        return verdictRowElement(r, {
          key: i,
          isOpen,
          onToggle: () => setExpanded((prev) => Object.assign({}, prev, { [key]: !prev[key] })),
        })
      })
      bodyChildren.push(createElement('ul', { className: 'dsg-list' }, rowElements))
    } else if (tab === 'model') {
      // The model-review tab: per-hook prompt templates. Edits land in a
      // tab-local draft and persist through the tab's own Save / Reload
      // buttons (the settings section keeps instant persistence).
      bodyChildren.push(el(ModelReviewTab, null))
    } else {
      const cfg: ReturnType<typeof el>[] = []
      const count = eff && Array.isArray(eff.policies) ? eff.policies.length : 0
      const baseCount = eff && Array.isArray(eff.policies)
        ? (eff.policies as Array<Record<string, unknown>>).filter((p) => String((p as { id?: unknown }).id || '').trim().startsWith('base-')).length
        : 0
      // Status line mirrors the model-review tab: enabled state (master
      // switch gates the rule stage) + policy inventory with the baseline /
      // custom breakdown. Source file and table version dropped as noise.
      const rulesOn = getGuardEnabled() && getRulesEnabled()
      cfg.push(el('div', { className: 'dsg-src' },
        t(rulesOn ? 'tabConfigStatusOn' : 'tabConfigStatusOff')
        + ' \u00b7 ' + t('configCounts', {
          count,
          baseCount,
          customCount: count - baseCount,
        })))
      if (eff && eff.error) cfg.push(el('div', { className: 'dsg-banner dsg-banner-danger' },
        t('syncError', { error: eff.error })))
      if (!rawOpen && draft.length === 0) {
        cfg.push(el('div', { className: 'dsg-banner' },
          t('noPoliciesBanner')))
      }
      cfg.push(el('datalist', { id: 'dsg-fields' },
        FIELD_OPTIONS.map((f) => el('option', { key: f, value: f }))))
      cfg.push(el('datalist', { id: 'dsg-values' },
        VALUE_OPTIONS.map((v) => el('option', { key: v, value: v }))))
      if (rawOpen) {
        cfg.push(el('textarea', {
          className: 'dsg-textarea',
          value: rawText,
          onChange: (e: { target: { value: string } }) => setRawText(e.target.value),
          spellCheck: false,
        }))
        cfg.push(el('div', { className: 'dsg-note' },
          t('jsonHint')))
        cfg.push(el('div', { className: 'dsg-actions' },
          el('button', { type: 'button', className: 'dsg-action', onClick: applyRaw, disabled: busy }, t('applyJson'))
        ))
      } else {
        if (draft.length === 0) {
          cfg.push(el('div', { className: 'dsg-note' }, t('noPoliciesNote')))
        }
        // Hook filter chips (mirrors the model-review tab): one chip per
        // native hook plus All, each with the count of policies bound to it.
        // Rendered above the list; only meaningful outside raw-JSON mode.
        cfg.push(el('div', { className: 'dsg-filters' },
          [{ key: 'all', label: t('filterAll') }, ...POLICY_HOOKS.map((h) => ({ key: h, label: h }))].map(({ key, label }) => {
            const count = key === 'all' ? draft.length : draft.filter((p) => p.hooks.includes(key)).length
            return el('button', {
              type: 'button',
              key,
              className: 'dsg-filter' + (hookFilter === key ? ' dsg-filter-on' : ''),
              onClick: () => setHookFilter(key),
            },
              el('span', null, label),
              el('span', { className: 'dsg-fcount' }, String(count)))
          })
        ))
        // Action row sits BELOW the hook filter: the chips scope the list the
        // buttons act on (and "Add Policy" inherits the active hook filter).
        cfg.push(el('div', { className: 'dsg-actions' },
          el('button', { type: 'button', className: 'dsg-action', onClick: addPolicy, disabled: busy }, t('addPolicy')),
          el('button', { type: 'button', className: 'dsg-action', onClick: openRaw, disabled: busy }, t('jsonView'))
        ))
        const matchHook = (p: DraftPolicy): boolean => hookFilter === 'all' || p.hooks.includes(hookFilter)
        const renderPolicy = (p: DraftPolicy) =>
          el(PolicyEditor, {
            key: p.key,
            policy: p,
            onPatch: (key: number, patch: Partial<DraftPolicy>) => setDraft((d) => patchPolicyIn(d, key, patch)),
            // Note: this is wired to `onClick: onDelete` in PolicyEditor, and
            // React passes the MouseEvent as the first argument. So it must be
            // a zero-arg closure capturing the policy key, never a `(key)`
            // handler. Otherwise the event object would be compared against policy
            // keys and the delete would silently no-op.
            onDelete: () => {
              if (window.confirm(t('deleteConfirm', { id: p.id || '(unnamed)' }))) {
                setDraft((d) => removePolicyIn(d, p.key))
              }
            },
          })
        const customs = draft.filter((p) => !isBasePolicy(p) && matchHook(p))
        const bases = draft.filter((p) => isBasePolicy(p) && matchHook(p))
        if (customs.length === 0 && bases.length === 0 && draft.length > 0) {
          cfg.push(el('div', { className: 'dsg-note' }, t('noHookMatches', { hook: hookFilter })))
        }
        // Custom policies first, since they are the operator's own rules.
        // Then the built-in baseline, collapsed by default so it never drowns the list.
        for (const p of customs) cfg.push(renderPolicy(p))
        if (bases.length > 0) {
          cfg.push(el('div', { className: 'dsg-group-title' },
            el('span', null, t('groupBaseline')),
            el('span', { className: 'dsg-group-count' }, t('policiesCount', { count: String(bases.length) })),
            el('button', {
              type: 'button',
              className: 'dsg-group-toggle',
              onClick: () => setBaseOpen((v) => !v),
            }, baseOpen ? '\u25be ' + t('hideBaseline') : '\u25b8 ' + t('showBaseline'))
          ))
          if (baseOpen) for (const p of bases) cfg.push(renderPolicy(p))
        }
      }
      bodyChildren.push(el('div', null, cfg))
      // Save/reload + status/error live in the pinned footer, not the
      // scrollable body, so they stay on screen with a long rule list.
      footerChildren.push(el('div', { className: 'dsg-actions' },
        el('button', { type: 'button', className: 'dsg-action', onClick: () => { void savePolicies() }, disabled: busy },
          busy ? t('saving') : t('save')),
        el('button', { type: 'button', className: 'dsg-action', onClick: () => { void loadEffective() }, disabled: busy },
          t('reload'))
      ))
      if (cfgStatus) footerChildren.push(el('div', { className: 'dsg-ok' }, cfgStatus))
      if (cfgError) footerChildren.push(el('div', { className: 'dsg-error' }, cfgError))
    }
    children.push(createElement('div', {
      // One uniform width on every tab — no per-tab resize.
      className: 'dsg-panel',
      role: 'dialog',
      'aria-label': t('panelTitle'),
    },
      createElement('div', { className: 'dsg-header' },
        createElement('div', { className: 'dsg-title' }, t('panelTitle')),
        createElement('button', { type: 'button', className: 'dsg-action', onClick: togglePanel }, t('closePanel'))
      ),
      createElement('div', { className: 'dsg-body' }, bodyChildren),
      tab === 'config'
        ? createElement('div', { className: 'dsg-footer' }, footerChildren)
        : tab === 'model'
          ? el(ModelFooter, null)
          : null
    ))
  }
  return createElement('div', { className: 'dsg-root' }, children)
}

/**
 * The conversation-view Security Review tab body: the current session's guard
 * verdict trail (`/guard/api/verdicts?sessionId=…`), polled every 4s while the
 * tab is mounted. Session-scoped by the `conversation.view` slot. Each
 * session sees its own verdicts, including sub-agent sessions.
 */
function GuardReviewView(props: { sessionId?: string }): ReturnType<typeof createElement> {
  const [rows, setRows] = useState<GuardVerdictRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  useLang()
  // Static review chain: the effective policy table is fetched once per
  // mount (config-derived — never from runtime rows) and reversed into
  // per-hook bindings for the horizontal chain at the top of the tab.
  const [scTable, setScTable] = useState<DraftPolicy[] | null>(null)
  useEffect(() => {
    let alive = true
    guardApi.getPolicies()
      .then((res) => {
        if (alive) setScTable(res && res.ok ? policiesToDraft((res.data && res.data.policies) || []) : null)
      })
      .catch(() => { /* rule-stage counts degrade to unknown */ })
    return () => {
      alive = false
    }
  }, [])

  // A session-scoped view must never fall back to the unfiltered (all-session)
  // verdict trail. That is what makes switching tabs show identical logs. If
  // the framework did not hand us the current session id, refuse to fetch and
  // surface an empty state instead of leaking every session's verdicts.
  const sessionId = props.sessionId ?? ''
  // Incremental cursor: each poll asks for rows newer than the last seq seen,
  // instead of re-sending the full trail every 4 s (N9). GuardVerdictRow seqs
  // are monotone; a cleared audit file resets them, so a re-assembly detects
  // non-monotonic rows and falls back to a full refetch.
  const nextSeqRef = useRef<number>(0)
  const refresh = useCallback(async (silent?: boolean) => {
    if (sessionId === '') {
      setLoading(false)
      setError('')
      setRows([])
      return
    }
    if (!silent) setLoading(true)
    try {
      const after = nextSeqRef.current
      const result = await guardApi.verdicts(sessionId, after)
      const fresh = Array.isArray(result) ? result : []
      if (fresh.length === 0) {
        setError('')
        if (!silent) setLoading(false)
        return
      }
      let maxSeq = 0
      let nonMonotonic = false
      for (const r of fresh) {
        if (r.seq > nextSeqRef.current) maxSeq = Math.max(maxSeq, r.seq)
        else nonMonotonic = true
      }
      if (nonMonotonic) {
        // seq reset (audit file truncated): refetch everything and rebuild.
        const all = await guardApi.verdicts(sessionId)
        setRows(Array.isArray(all) ? all : [])
        maxSeq = 0
        for (const r of Array.isArray(all) ? all : []) if (typeof r.seq === 'number') maxSeq = Math.max(maxSeq, r.seq)
        nextSeqRef.current = maxSeq
      } else {
        setRows((prev) => {
          const seen = new Map(prev.map((r) => [r.sessionId + ':' + String(r.seq), r]))
          for (const r of fresh) seen.set(r.sessionId + ':' + String(r.seq), r)
          return [...seen.values()].sort((a, b) => a.seq - b.seq)
        })
        nextSeqRef.current = Math.max(maxSeq, nextSeqRef.current)
      }
      setError('')
    } catch (e) {
      if (!silent) setError(e instanceof Error ? e.message : String(e))
    } finally {
      if (!silent) setLoading(false)
    }
  }, [sessionId])

  useEffect(() => {
    void refresh(false)
    const dispose = every(() => { void refresh(true) }, 4000)
    return () => { dispose() }
  }, [refresh])

  let pass = 0
  let deny = 0
  let ask = 0
  let warn = 0
  for (const r of rows) {
    if (r.outcome === 'deny') deny += 1
    else if (r.outcome === 'ask') ask += 1
    else if (r.outcome === 'warn') warn += 1
    else pass += 1
  }

  const children: ReturnType<typeof createElement>[] = []
  children.push(createElement('div', { className: 'dsg-summary' }, t('summary', { deny, ask, warn, pass })))
  if (error) children.push(createElement('div', { className: 'dsg-error' }, error))
  if (loading && rows.length === 0) children.push(createElement('div', { className: 'dsg-note' }, t('loading')))
  if (!loading && rows.length === 0 && !error) children.push(createElement('div', { className: 'dsg-note' }, t('noVerdicts')))

  // ── Static review chain (config-derived, NOT runtime): one stage per
  // native hook in lifecycle order; under each stage, the policies (rule
  // stage) and templates (model stage) that would activate there. Reversed
  // from the effective table + model-review prefs, fetched once per mount.
  const mr = getModelReview()
  const guardOn = getGuardEnabled()
  const rulesOn = getRulesEnabled()
  const modelOn = mr.enabled === true
  const scTemplates: ReviewTemplateLike[] = Array.isArray(mr.templates) ? mr.templates : []
  const scBaselines: ReviewTemplateLike[] = Array.isArray(mr.baselineTemplates) ? mr.baselineTemplates : []
  // Lifecycle order of the native seams (a request flows left → right).
  const SC_ORDER = [
    'agent/session-start',
    'agent/pre-step',
    'tools/pre-execute',
    'tools/guard',
    'tools/post-execute',
    'tools/result',
    'agent/turn-stopping',
    'subagent/start',
    'subagent/end',
  ]
  const stages: ReturnType<typeof createElement>[] = []
  SC_ORDER.forEach((hook, idx) => {
    const observeOnly = OBSERVE_ONLY_HOOKS.includes(hook)
    const pols = scTable !== null ? scTable.filter((p) => p.hooks.includes(hook)) : null
    const tpls = scTemplates.filter((tpl) => tpl.enabled !== false && templateHooksOf(tpl).includes(hook as TheGuardHook))
    const bls = scBaselines.filter((tpl) => tpl.enabled !== false && templateHooksOf(tpl).includes(hook as TheGuardHook))
    const modelActive = modelOn && (tpls.length > 0 || bls.length > 0)
    // Rule-stage card: bound policies (custom ids highlighted, baseline dim).
    const ruleChips: ReturnType<typeof createElement>[] = []
    if (rulesOn && pols !== null) {
      for (const p of pols) {
        const label = p.id !== '' ? p.id : '\u2014'
        ruleChips.push(createElement('span', {
          key: p.key,
          className: 'dsg-sc-pol' + (isBasePolicy(p) ? '' : ' dsg-sc-pol-custom'),
          title: policyHoverTitle(p),
        }, label))
      }
      if (pols.length === 0) ruleChips.push(createElement('span', { className: 'dsg-sc-empty' }, t('scNoRules')))
    }
    stages.push(createElement('div', {
      key: hook,
      className: 'dsg-sc-stage' + (observeOnly ? ' dsg-sc-dim' : ''),
    },
      createElement('span', {
        className: 'dsg-sc-node',
        title: hookStageTitle(hook),
      }, hook + (observeOnly ? ' \u00b7 ' + t('chainObserveOnly') : '')),
      createElement('div', { className: 'dsg-sc-cards' },
        createElement('div', {
          className: 'dsg-sc-card' + (rulesOn ? '' : ' dsg-sc-card-off'),
          title: rulesOn ? t('scRulesCardTitle') : undefined,
        },
          createElement('div', { className: 'dsg-sc-card-h' },
            rulesOn
              ? t('scStageRules', { count: pols === null ? '\u2014' : pols.length })
              : t('scRulesOff')),
          ruleChips),
        createElement('div', {
          className: 'dsg-sc-card' + (modelActive ? '' : ' dsg-sc-card-off'),
          title: modelActive ? t('scModelCardTitle') : undefined,
        },
          createElement('div', { className: 'dsg-sc-card-h' },
            !modelOn
              ? t('scModelOff')
              : !modelActive
                ? t('scNoBinding')
                : t('scModelCount', { count: tpls.length + bls.length })),
          modelActive
            ? tpls.map((tpl) => createElement('span', {
                key: tpl.id,
                className: 'dsg-sc-pol dsg-sc-pol-custom',
                title: templateHoverTitle(tpl),
              }, tpl.name !== '' ? tpl.name : t('mrTplNamePlaceholder')))
            : null,
          modelActive
            ? bls.map((tpl) => createElement('span', {
                key: 'base-' + tpl.id,
                className: 'dsg-sc-pol',
                title: templateHoverTitle(tpl),
              }, tpl.name !== '' ? templateName(tpl.id, tpl.name) : t('mrTplNamePlaceholder')))
            : null))))
    if (idx < SC_ORDER.length - 1) stages.push(createElement('div', { key: hook + '-link', className: 'dsg-sc-link' }))
  })

  const body: ReturnType<typeof createElement>[] = []
  for (const r of rows.slice(0, 200)) {
    const key = r.sessionId + ':' + String(r.seq)
    const isOpen = expanded[key] === true
    body.push(verdictTableRow(r, {
      key: 'r-' + key,
      isOpen,
      onToggle: () => setExpanded((prev) => Object.assign({}, prev, { [key]: !prev[key] })),
    }))
    if (isOpen) body.push(verdictTableDetailRow(r, 'd-' + key))
  }
  children.push(createElement('table', { className: 'dsg-table' },
    createElement('thead', { className: 'dsg-t-head' },
      createElement('tr', null,
        createElement('th', { scope: 'col' }, t('thTime')),
        createElement('th', { scope: 'col' }, t('thOutcome')),
        createElement('th', { scope: 'col' }, t('thType')),
        createElement('th', { scope: 'col' }, t('thHook')),
        createElement('th', { scope: 'col' }, t('thTool')),
        createElement('th', { scope: 'col' }, t('thMessage')),
        createElement('th', { scope: 'col', className: 'dsg-t-expand' }, '')
      )
    ),
    createElement('tbody', { className: 'dsg-t-body' }, body)
  ))
  // The static chain sits BELOW the log table: the trail is the primary
  // content; the config-derived chain is the reference legend underneath.
  children.push(createElement('div', { className: 'dsg-sc-title' }, t('scTitle')))
  if (!guardOn) children.push(createElement('div', { className: 'dsg-note' }, t('scGuardOff')))
  children.push(createElement('div', { className: 'dsg-sc' }, stages))
  return createElement('div', { className: 'dsg-view', role: 'tabpanel' }, children)
}


/** Props shared by the template card editor. */
interface TemplateCardProps {
  tpl: ReviewTemplateLike
  /** Per-bound-hook chain position: one entry per hook in `tpl.hooks`. */
  orders: Array<{ hook: TheGuardHook; pos: number; total: number }>
  /** Controlled collapse (the rules-config policy card's `open`). */
  open: boolean
  onToggleOpen: () => void
  canUp: boolean
  canDown: boolean
  onPatch: (patch: Partial<ReviewTemplateLike>) => void
  onMove: (delta: -1 | 1) => void
  onDelete: () => void
  onEdit: () => void
  onView: () => void
  /** True = this card's draft differs from the saved store (draft mode:
   * editable fields carry the amber .dsg-dirty marker). */
  dirty?: boolean
}

/** The template + baseline binding surface: every native seam, typed. */
const TEMPLATE_HOOKS = POLICY_HOOKS as TheGuardHook[]

/**
 * Which guard actions each built-in baseline template can produce, mirrored
 * from the server-side category tables (model-review.ts: USER_REQUEST /
 * AGENT_BEHAVIOR / INTENT_DRIFT action maps — the same split the two-line and
 * JSON parsers apply). Keyed by the shipped template id; an unknown id hides
 * the row (the client cannot know a template it was never shipped).
 */
const BASELINE_TEMPLATE_ACTIONS: Record<string, Array<'allow' | 'block' | 'ask' | 'warn'>> = {
  'malicious-intent-detection': ['allow', 'warn', 'block'],
  'risk-instruction-detection': ['allow', 'ask', 'block'],
  'intent-drift-detection': ['allow', 'ask'],
}

/** Chip title for a template-bound hook: same hints the policy editor uses. */
function templateHookHint(hook: string): string | undefined {
  if (OBSERVE_ONLY_HOOKS.includes(hook)) return t('hookObserveOnlyTitle')
  if (hook === 'tools/guard') return t('hookGuardTitle')
  return undefined
}

/**
 * Hover title for a static-chain hook node: what the seam fires on, plus the
 * observe-only / rule-only annotations when they apply.
 */
function hookStageTitle(hook: string): string {
  const desc: Record<string, string> = {
    'agent/session-start': t('hookDescSessionStart'),
    'agent/pre-step': t('hookDescPreStep'),
    'tools/pre-execute': t('hookDescPreExecute'),
    'tools/guard': t('hookDescGuard'),
    'tools/post-execute': t('hookDescPostExecute'),
    'tools/result': t('hookDescResult'),
    'agent/turn-stopping': t('hookDescTurnStopping'),
    'subagent/start': t('hookDescSubagentStart'),
    'subagent/end': t('hookDescSubagentEnd'),
  }
  const notes: string[] = []
  if (OBSERVE_ONLY_HOOKS.includes(hook)) notes.push(t('hookObserveOnlyTitle'))
  if (hook === 'tools/guard') notes.push(t('hookGuardTitle'))
  return hook + '\n' + (desc[hook] ?? '') + (notes.length > 0 ? '\n' + notes.join('\n') : '')
}

/**
 * Hover title for a policy chip: the policy's own specifics — id, action,
 * priority, its matching rules (up to 4) and the verdict message.
 */
function policyHoverTitle(p: DraftPolicy): string {
  const actionLbl = p.action === 'allow' ? t('actionAllow')
    : p.action === 'block' ? t('actionBlock')
    : p.action === 'ask' ? t('actionAsk')
    : p.action === 'warn' ? t('actionWarn') : p.action
  const lines = [p.id !== '' ? p.id : t('scNoId'), t('policyTitleAction', { action: actionLbl, priority: p.priority })]
  if (p.rules.length > 0) {
    lines.push(t('policyTitleRules', { count: p.rules.length }))
    for (const r of p.rules.slice(0, 4)) {
      lines.push('\u00b7 ' + r.field + ' ' + r.operator + (r.valueText !== '' ? ' ' + r.valueText.slice(0, 40) : ''))
    }
    if (p.rules.length > 4) lines.push('\u2026')
  }
  if (p.message !== '') lines.push(t('policyTitleMessage', { message: p.message.slice(0, 80) }))
  return lines.join('\n')
}

/** Hover title for a template chip: the template's own name, hooks, prompt. */
function templateHoverTitle(tpl: ReviewTemplateLike): string {
  const lines = [tpl.name !== '' ? templateName(tpl.id, tpl.name) : t('mrTplNamePlaceholder'), t('templateTitleHooks', { hooks: templateHooksOf(tpl).join(', ') })]
  const prompt = tpl.prompt !== '' ? tpl.prompt : t('templateTitleDefaultPrompt')
  lines.push(t('templateTitlePrompt') + ': ' + prompt.slice(0, 160) + (prompt.length > 160 ? '\u2026' : ''))
  return lines.join('\n')
}

/**
 * One custom review-template card, aligned with the rule-config policy card:
 * the same collapsible `.dsg-pcard` chrome — head row (CUSTOM badge, enable
 * checkbox, name, expand arrow, delete) over a body that only renders when
 * open: a MULTI-select hook chip row (the same 9-seam surface the policy
 * editor offers; a template joins every listed hook's chain), the
 * execution-order field (per-hook chain position + the ↑/↓ reorder buttons),
 * then the read-only prompt preview with an ✎ edit button that opens the
 * full-screen prompt editor; empty = the built-in default template.
 */
function TemplateCard(props: TemplateCardProps): ReturnType<typeof createElement> {
  const { tpl, orders, open } = props
  // Disposition cap: the strictest verdict this template may deliver — the
  // engine clamps a stricter model verdict down to it. Rendered in the head
  // right after the name (mirroring the baseline cards) so it is visible
  // without expanding. A binding whose hooks are ALL observe-only — where no
  // verdict can ever interrupt the run — narrows the choices to allow/warn
  // (same rule as the rule-config policy editor).
  const cap = tpl.action ?? 'block'
  const allObserveOnly = tpl.hooks.length > 0 && tpl.hooks.every((h) => OBSERVE_ONLY_HOOKS.includes(h))
  const actionOptions: TemplateAction[] = allObserveOnly
    ? TEMPLATE_ACTIONS.filter((a) => a === 'allow' || a === 'warn')
    : [...TEMPLATE_ACTIONS]
  const head = el('div', { className: 'dsg-pcard-head' },
    el('span', { className: 'dsg-badge dsg-badge-custom' }, t('badgeCustom')),
    el('input', {
      type: 'checkbox',
      checked: tpl.enabled,
      title: t('enabledTitle'),
      onChange: (e: { target: { checked: boolean } }) => props.onPatch({ enabled: e.target.checked }),
    }),
    el('input', {
      className: 'dsg-input' + (props.dirty === true ? ' dsg-dirty' : ''),
      value: tpl.name,
      placeholder: t('mrTplNamePlaceholder'),
      onChange: (e: { target: { value: string } }) => props.onPatch({ name: e.target.value }),
    }),
    // Disposition action in the head, mirroring the baseline cards' read-only
    // dropdown — but editable: picks this template's cap. The hover explains
    // the semantics; an all-observe-only binding narrows it to allow/warn.
    el('select', {
      className: 'dsg-select',
      value: actionOptions.indexOf(cap) !== -1 ? cap : 'warn',
      title: t('dispositionHint'),
      onChange: (e: { target: { value: string } }) => props.onPatch({ action: e.target.value as TemplateAction }),
    },
      actionOptions.map((a) => el('option', { key: a, value: a },
        a === 'allow' ? t('actionAllow')
          : a === 'block' ? t('actionBlock')
          : a === 'ask' ? t('actionAsk') : t('actionWarn')))
    ),
    el('button', {
      type: 'button',
      className: 'dsg-iconbtn',
      title: open ? t('collapseTitle') : t('expandTitle'),
      onClick: props.onToggleOpen,
    }, open ? '\u25be' : '\u25b8'),
    el('button', {
      type: 'button',
      className: 'dsg-iconbtn dsg-iconbtn-danger',
      title: t('mrTplDelete'),
      onClick: props.onDelete,
    }, '\u2715')
  )
  const body: ReturnType<typeof el>[] = []
  if (open) {
    // Hook binding: MULTI-select chips over the full 9-seam surface — the
    // same surface the rule-config policy editor offers. The template runs
    // in every listed hook's chain (observe-only seams = audit-only row;
    // tools/guard never runs the model stage).
    body.push(el('div', { className: 'dsg-field' },
      el('span', { className: 'dsg-label' }, t('labelHooks')),
      el('div', { className: 'dsg-chiprow' },
        TEMPLATE_HOOKS.map((h) =>
          el('button', {
            type: 'button',
            key: h,
            // Multi-select: toggle each hook in/out of the binding.
            className: 'dsg-chip' + (tpl.hooks.includes(h) ? ' dsg-chip-on' : ''),
            'aria-pressed': tpl.hooks.includes(h),
            title: templateHookHint(h),
            onClick: () => {
              const nextHooks = tpl.hooks.includes(h) ? tpl.hooks.filter((x) => x !== h) : [...tpl.hooks, h]
              // Re-normalize the disposition cap against the new binding:
              // an all-observe-only chain can never interrupt, so a block/
              // ask cap clamps down to warn (the strictest deliverable).
              const nextAction = normalizeTemplateAction(tpl.action, nextHooks)
              props.onPatch({
                hooks: nextHooks,
                ...(nextAction !== undefined && nextAction !== tpl.action ? { action: nextAction } : {}),
              })
            },
          }, h)
        )
      ),
      tpl.hooks.length === 0 ? el('div', { className: 'dsg-note' }, t('mrTplNoHooks')) : null,
      // The head's disposition select narrows on an all-observe-only binding;
      // the note sits right under the chips that drive it, saying why.
      allObserveOnly ? el('div', { className: 'dsg-note' }, t('dispositionObserveOnly')) : null
    ))
    // Execution order mirrors the policy card's priority field: the chain
    // position within EACH bound hook (multi-select joins several chains),
    // reordered through the ↑/↓ buttons beside it.
    body.push(el('div', { className: 'dsg-field' },
      el('span', { className: 'dsg-label' }, t('mrTplOrderLabel')),
      el('div', { className: 'dsg-pcard-order' },
        el('span', { className: 'dsg-meta' },
          orders.length === 0
            ? t('mrTplNoHooks')
            : orders.map((o) => t('mrTplOrderLine', { hook: o.hook, pos: String(o.pos + 1), total: String(o.total) })).join('\n')),
        el('button', {
          type: 'button',
          className: 'dsg-iconbtn',
          title: t('mrTplMoveUp'),
          disabled: !props.canUp,
          onClick: () => props.onMove(-1),
        }, '\u2191'),
        el('button', {
          type: 'button',
          className: 'dsg-iconbtn',
          title: t('mrTplMoveDown'),
          disabled: !props.canDown,
          onClick: () => props.onMove(1),
        }, '\u2193')
      )
    ))
    body.push(el('div', { className: 'dsg-field' },
      el('span', { className: 'dsg-label' }, t('modelReviewPromptLabel')),
      el('textarea', {
        className: 'dsg-textarea dsg-textarea-sm' + (props.dirty === true ? ' dsg-dirty' : ''),
        readOnly: true,
        rows: 3,
        value: tpl.prompt,
        spellCheck: false,
        placeholder: t('mrTplPromptEmptyHint'),
        title: t('modelReviewPromptEditDesc'),
      }),
      el('div', { className: 'dsg-actions' },
        el('button', { type: 'button', className: 'dsg-action', onClick: props.onView },
          '\u{1F441} ' + t('modelReviewPromptView')),
        el('button', { type: 'button', className: 'dsg-action', onClick: props.onEdit },
          '\u270e ' + t('modelReviewPromptEdit'))),
    ))
  }
  return el('div', { className: 'dsg-pcard' }, head, body)
}

/**
 * The shield panel's Model Review tab: per-hook review-prompt templates. Reads the
 * shared model-review store (the same state the settings section writes), so
 * the master switch / mode / endpoint stay in Settings while this tab owns
 * the prompts. Edits land in a tab-local draft; Save commits it through
 * /guard/api/prefs, Reload re-reads the server and drops the draft (the
 * rule-config tab's semantics). The settings section keeps instant
 * persistence for the master switch / mode / endpoint.
 *
 * Layout mirrors the rule-config tab: a read-only status line, a hook filter
 * chip row, the custom template cards (each bound to ONE hook; within a hook
 * the list order is the execution priority), and the collapsed built-in
 * baseline group
 * holding the default template — its front checkbox gates whether the global
 * prompt runs as the first template of every hook's chain.
 */
function ModelReviewTab(): ReturnType<typeof createElement> {
  useLang()
  const mr = getModelReview()
  // What the tab renders: the store mirror IS the draft — edits land there
  // instantly (triggers a re-render via useLang's preference subscription)
  // while nothing reaches the server until Save. Normalized to the multi-hook
  // array (legacy v0.1.x single `hook` collapses here) so filters, ordering
  // and saves all work in native naming. The baseline side is read-only
  // except each card's `enabled` flag.
  const templates: ReviewTemplateLike[] = Array.isArray(mr.templates)
    ? mr.templates.map(mrNormalizeTpl)
    : []
  const baselines: ReviewTemplateLike[] = Array.isArray(mr.baselineTemplates)
    ? mr.baselineTemplates.map(mrNormalizeTpl)
    : []
  const [filter, setFilter] = useState<'all' | string>('all')
  // Which custom-template prompt editor is open (by template id).
  const [editing, setEditing] = useState<string | null>(null)
  // Which template's full prompt is being VIEWED in the read-only dialog
  // (`'baseline:' + id` for a baseline card, the custom template id otherwise);
  // a separate state so the read-only viewer coexists with the ✎ editor.
  const [viewing, setViewing] = useState<string | null>(null)
  // Per-template collapse, mirroring the rules-config policy card's `open`:
  // loaded cards start collapsed; a freshly added template starts expanded.
  const [openIds, setOpenIds] = useState<Record<string, boolean>>({})
  // The built-in baseline templates group starts EXPANDED so the shipped
  // baseline cards are visible without an extra click; users can still collapse it.
  const [baselineOpen, setBaselineOpen] = useState(true)
  // Per-baseline-card body collapse (the group toggle above only shows/hides
  // the whole group, like the rules tab's built-in baseline group).
  const [baselineOpenBody, setBaselineOpenBody] = useState<Record<string, boolean>>({})

  // Dirty/busy/status and the Save/Reload handlers live in module scope
  // (mrIsDirty / setMrUi / mrSaveDraft / mrReloadDraft): the pinned footer
  // under the body renders them, and module state keeps the click handlers
  // immune to the test harness's state-slot shifting.

  // Per-card dirty: the card differs from its saved counterpart (a card
  // absent from the saved table — freshly added — is dirty always).
  const tplDirty = (tpl: ReviewTemplateLike): boolean => {
    const saved = mrSavedTemplates.find((s) => s.id === tpl.id)
    if (saved === undefined) return true
    return saved.name !== tpl.name || saved.enabled !== tpl.enabled
      || saved.prompt !== tpl.prompt || saved.hooks.join(',') !== tpl.hooks.join(',')
      || saved.action !== tpl.action
  }

  const patchTemplates = (next: ReviewTemplateLike[]): void => {
    // The store mirror IS the draft: writes stay local until Save.
    setModelReview({ templates: next })
  }
  const patchTemplate = (id: string, p: Partial<ReviewTemplateLike>): void => {
    patchTemplates(templates.map((tpl) => (tpl.id === id ? { ...tpl, ...p } : tpl)))
  }
  const removeTemplate = (id: string): void => {
    if (!confirmDestructive(t('mrTplDelete') + '?')) return
    patchTemplates(templates.filter((tpl) => tpl.id !== id))
  }
  const addTemplate = (): void => {
    const id = 'tpl-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6)
    const hooks: TheGuardHook[] = [filter === 'all' ? 'tools/pre-execute' : filter as TheGuardHook]
    // New templates start at full strength (block = uncapped); a template
    // seeded onto an observe-only seam starts at warn, the strictest action
    // that seam can deliver.
    const action: TemplateAction = OBSERVE_ONLY_HOOKS.includes(hooks[0]!) ? 'warn' : 'block'
    // New templates land at the top of their hook's chain (highest priority),
    // mirroring how new policies land at the top of the rule list — and open
    // so the name/hook/prompt fields are immediately at hand.
    patchTemplates([{ id, name: '', hooks, enabled: true, prompt: '', action }, ...templates])
    setOpenIds((prev) => ({ ...prev, [id]: true }))
  }
  const sharesHook = (a: ReviewTemplateLike, b: ReviewTemplateLike): boolean =>
    a.hooks.some((h) => b.hooks.includes(h))
  const moveTemplate = (id: string, delta: -1 | 1): void => {
    const index = templates.findIndex((tpl) => tpl.id === id)
    if (index === -1) return
    // Multi-select: a template sits in several chains at once, so "reorder"
    // swaps it with its NEAREST neighbor (in the move direction) that shares
    // at least one hook. Within every shared chain that is exactly an
    // adjacent swap; templates sharing no hook are never crossed.
    let target = index + delta
    while (target >= 0 && target < templates.length && !sharesHook(templates[index]!, templates[target]!)) {
      target += delta
    }
    if (target < 0 || target >= templates.length) return
    const next = templates.slice()
    const tmp = next[index]!
    next[index] = next[target]!
    next[target] = tmp
    patchTemplates(next)
  }
  const modeLabel = mr.mode === 'custom' ? t('modelReviewModeCustom') : t('modelReviewModeSession')
  // Built-in baseline template cards. Read-only name / hooks / prompt; only
  // `enabled` is editable (a disabled card is skipped entirely). The cards can
  // not be deleted or reordered — copy the text into a custom template instead.
  // Edits land in the draft like every custom-template edit (see Save above).
  const patchBaseline = (id: string, patch: Partial<ReviewTemplateLike>): void => {
    setModelReview({ baselineTemplates: baselines.map((tpl) => (tpl.id === id ? { ...tpl, ...patch } : tpl)) })
  }

  const children: ReturnType<typeof el>[] = []
  // Status line mirrors the rule-config tab's source line: enabled/mode plus
  // the template inventory (baseline cards + custom templates).
  children.push(el('div', { className: 'dsg-src' },
    (mr.enabled ? t('mrTabStatusOn') : t('mrTabStatusOff'))
    + ' \u00b7 ' + t('mrTabMode', { mode: modeLabel })
    + ' \u00b7 ' + t('mrTabCounts', { count: baselines.length + templates.length, baseCount: baselines.length, customCount: templates.length })))

  // Save/Reload, the unsaved banner and the status/error render in the
  // pinned footer under the scrollable body (ModelFooter) — the rule-config
  // tab's exact layout.

  // Hook filter chips (baseline + custom templates; multi-select bindings
  // match by inclusion). The counts mirror what the tab shows under each
  // filter: the baseline cards' fixed hook binding counts toward their hook
  // chip, so e.g. `tools/pre-execute` reports Risky Instruction Detection +
  // Intent Drift Detection too.
  children.push(el('div', { className: 'dsg-filters' },
    [{ key: 'all', label: t('filterAll') }, ...TEMPLATE_HOOKS.map((h) => ({ key: h, label: h }))].map(({ key, label }) => {
      const count = key === 'all'
        ? templates.length + baselines.length
        : templates.filter((tpl) => tpl.hooks.includes(key as TheGuardHook)).length
          + baselines.filter((tpl) => tpl.hooks.includes(key as TheGuardHook)).length
      return el('button', {
        type: 'button',
        key,
        className: 'dsg-filter' + (filter === key ? ' dsg-filter-on' : ''),
        onClick: () => setFilter(key),
      },
        el('span', null, label),
        el('span', { className: 'dsg-fcount' }, String(count)))
    })
  ))

  children.push(el('div', { className: 'dsg-actions' },
    el('button', { type: 'button', className: 'dsg-action', onClick: addTemplate }, t('mrTabAddTemplate'))))
  if (templates.length > 0) children.push(el('div', { className: 'dsg-note' }, t('mrTabPriorityHint')))

  const visible = filter === 'all' ? templates : templates.filter((tpl) => tpl.hooks.includes(filter as TheGuardHook))
  // The hook filter scopes the baseline group too, so the cards shown under a
  // filter match the chip's count (filter 'all' shows the whole table).
  const visibleBaselines = filter === 'all' ? baselines : baselines.filter((tpl) => tpl.hooks.includes(filter as TheGuardHook))
  if (visible.length === 0) children.push(el('div', { className: 'dsg-note' }, t('mrTabNone')))
  for (const tpl of visible) {
    // Chain position within EACH bound hook, computed over the full list
    // (the engine iterates every template, not just the filtered view).
    const orders = TEMPLATE_HOOKS
      .filter((h) => tpl.hooks.includes(h))
      .map((h) => {
        const chain = templates.filter((t2) => t2.hooks.includes(h))
        return { hook: h, pos: chain.indexOf(tpl), total: chain.length }
      })
      .filter((o) => o.pos !== -1)
    // ↑/↓ swap with the nearest hook-sharing neighbor (see moveTemplate).
    const index = templates.indexOf(tpl)
    const canUp = templates.slice(0, index).some((t2) => sharesHook(tpl, t2))
    const canDown = templates.slice(index + 1).some((t2) => sharesHook(tpl, t2))
    children.push(el(TemplateCard, {
      key: tpl.id,
      tpl,
      orders,
      open: openIds[tpl.id] === true,
      onToggleOpen: () => setOpenIds((prev) => ({ ...prev, [tpl.id]: !(prev[tpl.id] === true) })),
      canUp,
      canDown,
      onPatch: (patch: Partial<ReviewTemplateLike>) => patchTemplate(tpl.id, patch),
      onMove: (delta: -1 | 1) => moveTemplate(tpl.id, delta),
      onDelete: () => removeTemplate(tpl.id),
      onEdit: () => setEditing(tpl.id),
      onView: () => setViewing(tpl.id),
      dirty: tplDirty(tpl),
    }))
  }

  // The built-in baseline template cards: read-only name / hook binding /
  // prompt, with only the `enabled` switch editable. They cannot be deleted or
  // reordered (mirror the base-policy cards: a built-in badge, checkbox + name in
  // the head, fixed hook chips + read-only prompt in the body). A card with
  // `enabled` off is skipped entirely. The group follows the active hook
  // filter: under a hook chip only the baseline cards bound to that hook
  // render (matching the chip count); a filter with no baseline match hides
  // the whole group. The modals below must always render, so this is a
  // conditional push — not an early return.
  const showBaselines = visibleBaselines.length > 0
  if (showBaselines) children.push(el('div', { className: 'dsg-group-title' },
    el('span', null, t('mrBaselineGroup')),
    el('span', { className: 'dsg-group-count' }, t('mrBaselineCount', { count: String(visibleBaselines.length) })),
    el('button', {
      type: 'button',
      className: 'dsg-group-toggle',
      onClick: () => setBaselineOpen((v) => !v),
    }, baselineOpen ? '\u25be ' + t('hideBaseline') : '\u25b8 ' + t('showBaseline'))
  ))
  if (baselineOpen && showBaselines) {
    for (const tpl of visibleBaselines) {
      // Baseline card bodies stay folded; only the group header is expanded.
      const open = baselineOpenBody[tpl.id] === true
      const head = el('div', { className: 'dsg-pcard-head' },
        el('span', { className: 'dsg-badge dsg-badge-base' }, t('badgeBaseline')),
        el('input', {
          type: 'checkbox',
          checked: tpl.enabled,
          title: t('enabledTitle'),
          onChange: (e: { target: { checked: boolean } }) => patchBaseline(tpl.id, { enabled: e.target.checked }),
        }),
        el('span', { className: 'dsg-lang-label' }, tpl.name !== '' ? templateName(tpl.id, tpl.name) : t('mrTplNamePlaceholder')),
        // Disposition action (mirrors the rule-config card's action select):
        // a read-only dropdown in the head — visible without expanding —
        // listing the actions this shipped template can hand down (server-
        // fixed per id; the value shows the most severe one). Unknown ids
        // omit the select entirely.
        ...(BASELINE_TEMPLATE_ACTIONS[tpl.id] !== undefined
          ? [el('select', {
            className: 'dsg-select',
            value: BASELINE_TEMPLATE_ACTIONS[tpl.id]![BASELINE_TEMPLATE_ACTIONS[tpl.id]!.length - 1],
            disabled: true,
            title: t('mrBaselineMetaTitle'),
          },
            BASELINE_TEMPLATE_ACTIONS[tpl.id]!.map((a) =>
              el('option', { key: a, value: a },
                a === 'allow' ? t('actionAllow')
                  : a === 'block' ? t('actionBlock')
                  : a === 'ask' ? t('actionAsk') : t('actionWarn')))
          )]
          : []),
        el('button', {
          type: 'button',
          className: 'dsg-iconbtn',
          title: open ? t('collapseTitle') : t('expandTitle'),
          onClick: () => setBaselineOpenBody((prev) => ({ ...prev, [tpl.id]: !(prev[tpl.id] === true) })),
        }, open ? '\u25be' : '\u25b8'),
        // Where the delete button sits on a custom card, a baseline card
        // carries the ⚠ read-only explanation (mirrors the rule-config
        // baseline policy card's ⚠ / delete pairing).
        el('span', { className: 'dsg-meta', title: t('mrBaselineMetaTitle') }, '\u26a0')
      )
      const body = open ? el('div', null,
        el('div', { className: 'dsg-field' },
          el('span', { className: 'dsg-label' }, t('labelHooks')),
          // The full seam surface (mirrors the rule-config card's chip row):
          // every hook renders, the bound ones lit, all inert — the binding
          // is fixed and the card cannot be reordered or moved.
          el('div', { className: 'dsg-chiprow' },
            TEMPLATE_HOOKS.map((hook) =>
              el('button', {
                type: 'button',
                key: hook,
                className: 'dsg-chip' + (tpl.hooks.includes(hook) ? ' dsg-chip-on' : ''),
                title: templateHookHint(hook),
                disabled: true,
              }, hook))
          ),
          tpl.hooks.length === 0 ? el('div', { className: 'dsg-note' }, t('mrTplNoHooks')) : null
        ),
        el('div', { className: 'dsg-field' },
          el('span', { className: 'dsg-label' }, t('modelReviewPromptLabel')),
          el('textarea', {
            className: 'dsg-textarea dsg-textarea-sm',
            readOnly: true,
            rows: 3,
            value: tpl.prompt,
            spellCheck: false,
            title: t('mrBaselineReadonlyHint'),
          }),
          el('div', { className: 'dsg-actions' },
            el('button', { type: 'button', className: 'dsg-action', onClick: () => setViewing('baseline:' + tpl.id) },
              '\u{1F441} ' + t('modelReviewPromptView')))
          // The ⚠ head badge + the textarea hover title carry the read-only
          // explanation; no inline note (mirrors the rule-config card).
        )
      ) : null
      children.push(el('div', { className: 'dsg-pcard dsg-pcard-base' }, head, body))
    }
  }
  // All-shown-cards-disabled hint: scoped to the filtered view so it never
  // contradicts the cards actually on screen.
  if (showBaselines && visibleBaselines.every((tpl) => tpl.enabled === false)) {
    children.push(el('div', { className: 'dsg-note' }, t('mrBaselineOffHint')))
  }

  // The full-screen prompt dialog: the ✎ editor for custom templates, and the
// 👁 read-only viewer for both custom templates and the built-in baseline
// cards (baselines are read-only by design; a custom template left empty is
// skipped entirely at review time).
  const editingTemplate = editing !== null && !(editing ?? '').startsWith('baseline:')
    ? templates.find((tpl) => tpl.id === editing)
    : undefined
  let viewingValue: string | undefined
  let viewingTitle: string | undefined
  if (viewing !== null) {
    if (viewing.startsWith('baseline:')) {
      const viewed = baselines.find((tpl) => tpl.id === viewing.slice('baseline:'.length))
      viewingValue = viewed?.prompt
      viewingTitle = viewed === undefined
        ? ''
        : viewed.name !== '' ? templateName(viewed.id, viewed.name) : t('badgeBaseline')
    } else {
      const viewed = templates.find((tpl) => tpl.id === viewing)
      viewingValue = viewed?.prompt
      viewingTitle = viewed?.name !== '' ? (viewed?.name ?? '') : t('mrTplNamePlaceholder')
    }
  }
  const viewModal = viewing !== null && viewingValue !== undefined
    ? el(PromptEditorModal, {
      value: viewingValue,
      viewOnly: true,
      title: t('modelReviewPromptViewModalTitle', { name: viewingTitle ?? '' }),
      onPatch: () => {},
      onClose: () => setViewing(null),
    })
    : null
  return el('div', null, children,
    editing !== null && editingTemplate !== undefined
      ? el(PromptEditorModal, {
        value: editingTemplate!.prompt,
        dirty: tplDirty(editingTemplate!),
        title: t('mrTplModalTitle'),
        onPatch: (next: string) => patchTemplate(editing!, { prompt: next }),
        onClose: () => setEditing(null),
      })
      : null,
    viewModal
  )
}

/** The model-review tab's pinned footer: Save/Reload plus the unsaved-draft
 * banner and the save status/error — the rule-config footer's twin. Reads the
 * module-level draft bookkeeping (no props drilling through GuardPanel) and
 * re-renders via the tiny setMrUi subscription. */
function ModelFooter(): ReturnType<typeof createElement> {
  useMrUi()
  const children: ReturnType<typeof el>[] = []
  if (mrIsDirty()) children.push(el('div', { className: 'dsg-banner' }, t('mrTabDirty')))
  children.push(el('div', { className: 'dsg-actions' },
    el('button', { type: 'button', className: 'dsg-action', onClick: () => { void mrSaveDraft() }, disabled: mrBusy },
      mrBusy ? t('saving') : t('save')),
    el('button', { type: 'button', className: 'dsg-action', onClick: () => { void mrReloadDraft() }, disabled: mrBusy },
      t('reload')),
  ))
  if (mrStatus) children.push(el('div', { className: 'dsg-ok' }, mrStatus))
  if (mrError) children.push(el('div', { className: 'dsg-error' }, mrError))
  return el('div', { className: 'dsg-footer' }, children)
}

/**
 * The settings section for the Security Guard plugin (rendered in the DSH
 * Settings shell under a section registered at `settings.section`). The
 * language picker (auto / zh / en) and the conversation-tab visibility toggle
 * are persisted through the settings namespace; the panel, the view tab and
 * this section re-render immediately because the whole client bundle shares
 * the preference store in locales.ts.
 */
/**
 * Settings-row label column: the label plus a `?` hover bubble carrying the
 * description (replaces the old always-visible small print). The bubble
 * reuses the rule-editor help tip rendered into document.body, so the
 * settings shell's overflow containers never clip it. An empty description
 * renders no bubble (e.g. the hook-binding rows).
 */
function labelCol(label: string, desc: string): ReturnType<typeof createElement> {
  return createElement('div', { className: 'dsg-lang-col' },
    createElement('div', { className: 'dsg-flabel' },
      createElement('span', { className: 'dsg-lang-label' }, label),
      desc !== '' ? helpButton(desc) : null,
    ),
  )
}

/** One labeled checkbox row (settings section); description rides the `?` bubble. */
function checkRow(
  label: string,
  desc: string,
  checked: boolean,
  onToggle: (next: boolean) => void,
): ReturnType<typeof createElement> {
  return createElement('div', { className: 'dsg-lang-row' },
    labelCol(label, desc),
    createElement('input', {
      type: 'checkbox',
      className: 'dsg-check',
      checked,
      'aria-label': label,
      onChange: (e: { target: { checked: boolean } }) => { onToggle(e.target.checked) },
    })
  )
}

/**
 * The plugin's inline SVG shield glyph (stroke inherits `currentColor`, so it
 * recolors with the surrounding text/hover states). One source of truth for
 * every surface that shows the shield: the guard-panel header toggle and the
 * settings-nav label below.
 */
function shieldIcon(className: string, size: number): ReturnType<typeof createElement> {
  return createElement('svg', {
    className,
    viewBox: '0 0 16 16',
    width: size,
    height: size,
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.3,
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
    'aria-hidden': 'true',
  },
    createElement('path', { d: 'M8 1.75 13.4 3.6v4c0 3.3-2.3 5.7-5.4 6.75C4.9 13.3 2.6 10.9 2.6 7.6v-4z' }),
    createElement('path', { d: 'M5.9 8.05 7.35 9.5l2.8-3.1' }),
  )
}

/**
 * The settings-nav entry for this plugin. The DSH shell hardcodes section
 * icons by id (models / agent-presets / plugins; every other id falls back to
 * a generic gear) and the `settings.section` contract carries no icon field,
 * so a plugin cannot request a different glyph through public APIs. We ship a
 * real inline SVG shield as part of the label (resolveSlotLabel passes nodes
 * through unchanged) and hide the adjacent host gear with a :has()-scoped CSS
 * rule - see shieldIcon above.
 */
function settingsNavLabel(): ReturnType<typeof createElement> {
  return createElement('span', { className: 'dsg-nav-label' },
    shieldIcon('dsg-nav-icon', 16),
    t('settingsNav'),
  )
}

/**
 * One collapsible level-1 settings group (Review chain / Interface & language), modeled on the
 * harness plugin-config cards: a full-width header button naming the group
 * (plus an optional `?` hint) with a chevron that rotates when open, and a
 * bordered body disclosed in place. Collapse is local reading state — which
 * group a user has open is a reading gesture, not something persisted — and
 * the settings inside keep their values either way.
 */
function SettingsGroup({ title, hint, defaultOpen, children }: {
  title: string
  hint?: string
  defaultOpen?: boolean
  /** Group controls; React injects these from the element's children. */
  children?: ReactNode
}): ReturnType<typeof createElement> {
  const [open, setOpen] = useState(defaultOpen !== false)
  return createElement('div', { className: open ? 'dsg-card dsg-card-open' : 'dsg-card' },
    createElement('button', {
      type: 'button',
      className: 'dsg-card-head',
      'aria-expanded': open,
      onClick: () => { setOpen(!open) },
    },
      createElement('span', { className: 'dsg-card-text' },
        createElement('span', { className: 'dsg-card-name' },
          title,
          hint !== undefined ? helpButton(hint) : null,
        ),
      ),
      createElement('svg', {
        className: 'dsg-card-chev',
        width: 14,
        height: 14,
        viewBox: '0 0 14 14',
        'aria-hidden': true,
      },
        createElement('path', {
          d: 'M3 5.5l4 4 4-4',
          fill: 'none',
          stroke: 'currentColor',
          strokeWidth: 1.5,
          strokeLinecap: 'round',
          strokeLinejoin: 'round',
        })
      ),
    ),
    open
      ? createElement('div', { className: 'dsg-card-body' }, children)
      : null,
  )
}

/**
 * Ask the host to confirm an irreversible edit — the same native dialog the
 * policy-delete flow uses. A host with no dialog available (the module sandbox,
 * a webview that suppresses it) proceeds with what the click asked for instead
 * of throwing or silently no-op'ing: the dialog is a safety brake on an
 * accident, not a permission gate on the user's own intent.
 */
function confirmDestructive(message: string): boolean {
  if (typeof window === 'undefined' || typeof window.confirm !== 'function') return true
  return window.confirm(message)
}

/**
 * The editor for a custom review-prompt template, opened by the card's ✎ Edit
 * button.
 *
 * The card body itself is a read-only preview, far too small for a full audit
 * template (thousands of characters, dozens of risk categories). This dialog
 * fills the viewport with a monospace editor and owns every write to `prompt`.
 * Persistence saves as you type, so the read-only preview behind it is never
 * stale. `Esc`, the ✕, Done and a backdrop click all close it.
 *
 * The built-in baseline cards are read-only by design and never open this
 * editor; to customize a baseline prompt, copy its text into a custom
 * template here.
 *
 * The overlay renders inline in the tree (the client bundle has no react-dom,
 * so no portal) as a `position:fixed` layer above the settings shell, the way
 * `.dsg-panel` does for the header-seat panel.
 */
function PromptEditorModal(props: {
  value: string
  onPatch: (next: string) => void
  onClose: () => void
  /** View-only mode: read-only textarea, no edits, footer = just Done. */
  viewOnly?: boolean
  /** Dialog title; defaults to the template prompt's title. */
  title?: string
  /** True = the edited value differs from the saved store (draft mode):
   * the textarea carries the amber .dsg-dirty marker. */
  dirty?: boolean
}): ReturnType<typeof createElement> {
  const ref = useRef<HTMLTextAreaElement | null>(null)
  useEffect(() => {
    if (props.viewOnly !== true) ref.current?.focus?.()
    if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') return
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') props.onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => { window.removeEventListener('keydown', onKey) }
  }, [])
  const close = (): void => props.onClose()
  return createElement('div', {
    className: 'dsg-modal-mask',
    onMouseDown: (e: { target: unknown; currentTarget: unknown }) => {
      // Backdrop click only (the panel stops at the mask); typed loosely
      // because the DOM `target` is only narrowed at runtime here.
      if (e.target === e.currentTarget) close()
    },
  },
    createElement('div', {
      className: 'dsg-modal',
      role: 'dialog',
      'aria-modal': true,
      'aria-label': props.title ?? t('modelReviewPromptModalTitle'),
    },
      createElement('div', { className: 'dsg-modal-head' },
        createElement('span', { className: 'dsg-modal-title' }, props.title ?? t('modelReviewPromptModalTitle')),
        createElement('button', {
          type: 'button',
          className: 'dsg-iconbtn',
          title: t('modelReviewPromptClose'),
          'aria-label': t('modelReviewPromptClose'),
          onClick: close,
        }, '✕')
      ),
      createElement('div', { className: 'dsg-modal-body' },
        createElement('textarea', {
          ref,
          className: 'dsg-modal-textarea' + (props.dirty === true ? ' dsg-dirty' : ''),
          // `rows` is only the intrinsic fallback height; the injected CSS gives
          // the dialog a definite height and lets the field fill it.
          rows: 20,
          value: props.value,
          spellCheck: false,
          readOnly: props.viewOnly === true,
          placeholder: t('modelReviewPromptDesc'),
          onChange: (e: { target: { value: string } }) => { props.onPatch(e.target.value) },
        })
      ),
      createElement('div', { className: 'dsg-modal-foot' },
        createElement('span', { className: 'dsg-modal-meta' },
          t('modelReviewPromptChars', { count: String(props.value.length) })),
        createElement('button', {
          type: 'button',
          className: 'dsg-action',
          onClick: close,
        }, t('modelReviewPromptDone'))
      )
    )
  )
}

function LangSection(_props: GuardSettingsSectionProps): ReturnType<typeof createElement> {
  useLang()
  const pref = getPreference()
  const mr = getModelReview()
  const options: Array<{ value: GuardLocale; title: string; desc: string }> = [
    { value: 'auto', title: t('langDefault'), desc: t('langDefaultDesc') },
    { value: 'zh', title: t('langZh'), desc: t('langZhDesc') },
    { value: 'en', title: t('langEn'), desc: t('langEnDesc') },
  ]
  return createElement('div', { className: 'dsg-lang' },
    createElement('div', { className: 'dsg-lang-intro' }, t('settingsIntro')),
    // ── level-1 collapsible card: review chain & protection switches ──
    createElement(SettingsGroup, {
      title: t('chainTitle'),
      hint: t('chainDesc'),
      defaultOpen: true,
    },
      checkRow(t('guardEnabledLabel'), t('guardEnabledDesc'), getGuardEnabled(), (next) => { void persistGuardEnabled(next) }),
    checkRow(t('rulesEnabledLabel'), t('rulesEnabledDesc'), getRulesEnabled(), (next) => { void persistRulesEnabled(next) }),
    checkRow(t('modelReviewEnabledLabel'), t('modelReviewEnabledDesc'), mr.enabled, (next) => {
      if (next && mr.mode === 'session' && !confirmDestructive(t('modelReviewReuseTokenConfirm'))) return
      void persistModelReview({ enabled: next })
    }),
    createElement('div', { className: 'dsg-lang-row' },
      labelCol(t('modelReviewModeLabel'), t('modelReviewModeDesc')),
      createElement('select', {
        className: 'dsg-select dsg-lang-select',
        value: mr.mode,
        onChange: (e: { target: { value: string } }) => {
          const next = e.target.value
          if (next !== 'session' && next !== 'custom') return
          // Switching to (or restarting with) the reuse-session model means every
          // review now bills against the session model: ask for one more confirm.
          if (next === 'session' && mr.mode !== 'session' && !confirmDestructive(t('modelReviewReuseTokenConfirm'))) return
          void persistModelReview({ mode: next })
        },
      },
        createElement('option', { value: 'session', title: t('modelReviewModeSessionDesc') }, t('modelReviewModeSession')),
        createElement('option', { value: 'custom', title: t('modelReviewModeCustomDesc') }, t('modelReviewModeCustom'))
      )
    ),
    // Session-mode opt-in make-up switch (only meaningful in session mode):
    // the harness logs the model route on its FIRST dispatch, so a session's
    // first guarded event skips. The timing caveat now rides the row's `?`
    // bubble together with the make-up description.
    ...(mr.mode === 'session' ? [
      checkRow(
        t('modelReviewMakeupLabel'),
        t('modelReviewMakeupDesc') + ' ' + t('modelReviewModeSessionTiming'),
        mr.makeupReview === true,
        (next) => { void persistModelReview({ makeupReview: next }) },
      ),
    ] : []),
    // Endpoint config is only relevant in custom mode; in session mode show a
    // one-line hint instead (the session model route needs no config here).
    ...(mr.mode === 'custom'
      ? [
          createElement('div', { className: 'dsg-lang-row' },
            labelCol(t('modelReviewProtocolLabel'), t('modelReviewProtocolDesc')),
            createElement('select', {
              className: 'dsg-select dsg-lang-select',
              value: mr.protocol,
              onChange: (e: { target: { value: string } }) => {
                const value = e.target.value
                if (value === 'openai-chat' || value === 'openai-responses' || value === 'anthropic') void persistModelReview({ protocol: value })
              },
            },
              createElement('option', { value: 'openai-chat', title: t('modelReviewProtocolChatDesc') }, t('modelReviewProtocolChat')),
              createElement('option', { value: 'openai-responses', title: t('modelReviewProtocolResponsesDesc') }, t('modelReviewProtocolResponses')),
              createElement('option', { value: 'anthropic', title: t('modelReviewProtocolAnthropicDesc') }, t('modelReviewProtocolAnthropic'))
            )
          ),
          createElement('div', { className: 'dsg-lang-row' },
            labelCol(t('modelReviewBaseUrlLabel'), t('modelReviewModeCustomDesc')),
            createElement('input', {
              className: 'dsg-input',
              value: mr.baseUrl,
              placeholder: mr.protocol === 'anthropic'
                ? t('modelReviewBaseUrlAnthropicPlaceholder')
                : mr.protocol === 'openai-responses'
                  ? t('modelReviewBaseUrlResponsesPlaceholder')
                  : t('modelReviewBaseUrlPlaceholder'),
              onChange: (e: { target: { value: string } }) => { void persistModelReview({ baseUrl: e.target.value }) },
            })
          ),
          createElement('div', { className: 'dsg-lang-row' },
            labelCol(t('modelReviewApiKeyLabel'), t('modelReviewApiKeyDesc')),
            createElement('input', {
              className: 'dsg-input',
              type: 'password',
              value: mr.apiKey,
              placeholder: t('modelReviewApiKeyPlaceholder'),
              onChange: (e: { target: { value: string } }) => { void persistModelReview({ apiKey: e.target.value }) },
            })
          ),
          createElement('div', { className: 'dsg-lang-row' },
            labelCol(t('modelReviewModelLabel'), t('modelReviewModeCustomDesc')),
            createElement('input', {
              className: 'dsg-input',
              value: mr.model,
              placeholder: t('modelReviewModelPlaceholder'),
              onChange: (e: { target: { value: string } }) => { void persistModelReview({ model: e.target.value }) },
            })
          ),
          createElement('div', { className: 'dsg-lang-row' },
            labelCol(t('modelReviewThinkingLabel'), t('modelReviewThinkingDesc')),
            createElement('select', {
              className: 'dsg-select dsg-lang-select',
              value: mr.thinking,
              onChange: (e: { target: { value: string } }) => {
                const value = e.target.value
                if (value === 'default' || value === 'off' || value === 'low' || value === 'medium' || value === 'high') {
                  void persistModelReview({ thinking: value })
                }
              },
            },
              createElement('option', { value: 'default', title: t('modelReviewThinkingDefault') }, t('modelReviewThinkingDefault')),
              createElement('option', { value: 'off', title: t('modelReviewThinkingOff') }, t('modelReviewThinkingOff')),
              createElement('option', { value: 'low', title: t('modelReviewThinkingLow') }, t('modelReviewThinkingLow')),
              createElement('option', { value: 'medium', title: t('modelReviewThinkingMedium') }, t('modelReviewThinkingMedium')),
              createElement('option', { value: 'high', title: t('modelReviewThinkingHigh') }, t('modelReviewThinkingHigh'))
            )
          ),
        ]
      : []),
    // The call deadline applies to BOTH modes: the stage builds the abort
    // signal once and hands it to whichever caller serves the review, so the
    // timeout row renders outside the mode split. (Thinking stays custom-only:
    // it is wire-protocol specific, and the session model route carries its
    // own reasoning settings in the harness.)
    createElement('div', { className: 'dsg-lang-row' },
      labelCol(t('modelReviewTimeoutLabel'), t('modelReviewTimeoutDesc')),
      createElement('input', {
        className: 'dsg-input',
        type: 'number',
        min: 100,
        max: 60000,
        value: String(mr.timeoutMs),
        onChange: (e: { target: { value: string } }) => {
          const n = Number(e.target.value)
          if (Number.isFinite(n) && n > 0 && n <= 60000) void persistModelReview({ timeoutMs: n })
        },
      })
    ),
    // The review prompts moved to the shield panel's Model Review tab — the
    // settings section carries no pointer row for them (keep this comment so
    // the gap is not mistaken for a lost feature).
    ),
    // ── level-1 collapsible card: interface & language (display-only) ──
    createElement(SettingsGroup, {
      title: t('uiTitle'),
      defaultOpen: false,
    },
      createElement('label', { className: 'dsg-lang-row' },
        labelCol(t('langLabel'), ''),
      createElement('select', {
        className: 'dsg-select dsg-lang-select',
        value: pref,
        onChange: (e: { target: { value: string } }) => {
          const next = e.target.value
          if (next === 'auto' || next === 'zh' || next === 'en') {
            void persistLang(next)
          }
        },
      },
        options.map((o) =>
          createElement('option', {
            key: o.value,
            value: o.value,
            title: o.desc,
          }, o.title)
        )
      )
    ),
      checkRow(t('showTabLabel'), t('showTabDesc'), getShowTab(), (next) => { void persistShowTab(next) }),
      checkRow(t('showHeaderLabel'), t('showHeaderDesc'), getShowHeader(), (next) => { void persistShowHeader(next) }),
    ),
    // ── level-1 collapsible card: debug / audit-troubleshooting switches ──
    // Deliberately separate from the protection chain: recording allow
    // verdicts grows the audit log fast, so it is an opt-in debug aid.
    createElement(SettingsGroup, {
      title: t('debugTitle'),
      hint: t('debugDesc'),
      defaultOpen: false,
    },
      checkRow(t('recordAllowLabel'), t('recordAllowDesc'), getRecordAllow(), (next) => { void persistRecordAllow(next) }),
    )
  )
}

/**
 * Mount entry: register the panel into the session header utilities seat, the
 * language picker / tab-visibility toggle into the DSH Settings shell, and the
 * Security Review tab into the conversation view ring.
 *
 * The header seat is session-scoped, but the panel body is global (module
 * store + host-side fold across all sessions), so the same `apply` registers
 * it in every session header; all seats share one open-state and verdict
 * list. The settings section registers once (root-scoped slot), reads/writes
 * the preferences through the plugin's fenced routes, and the shared
 * preference store re-renders the panel and the view instantly on a switch.
 *
 * The `conversation.view` entry is registered/unregistered live from the
 * `showSessionTab` preference: toggling the setting shows or hides the tab
 * without reloading. The entry is session-scoped, so each session gets its own
 * Security Review tab showing that session's verdicts only.
 */
export function apply(ctx: GuardClientContext): void {
  const removeStyle = injectStyle()
  ctx.effect(() => () => removeStyle(), 'deepseek-harness-security-guard: styles')
  // Ride the DSH locale service (auto mode follows it live) and load the
  // persisted preferences. Failures keep the schema defaults silently.
  attachLocale(ctx.locale)
  ctx.effect(() => {
    void loadPrefs()
  }, 'deepseek-harness-security-guard: preferences load')
  // Report the effective locale to the host so host-generated messages (rule
  // save / review-log clear / approval reasons) follow the same language as
  // the panel: an explicit preference, or the DSH active locale in auto mode.
  // Re-reports on boot and whenever the preference or the DSH locale changes.
  const reportResolvedLocale = () => { void guardApi.setResolvedLocale(effectiveLocale()) }
  reportResolvedLocale()
  const unsubResolvedPref = subscribePreference(reportResolvedLocale)
  const unsubResolvedLoc = subscribeLocale(reportResolvedLocale)
  ctx.effect(() => () => { unsubResolvedPref(); unsubResolvedLoc() }, 'deepseek-harness-security-guard: resolved-locale report')

  // The "Security Guard" settings section: appears in the DSH Settings shell
  // once the shell's declaration is on the ledger (slots.inject waits for it);
  // the section renders the language picker, the view-tab toggle, the header
  // shield-button toggle and the global protection master switch, writing
  // through the plugin's own fenced routes.
  ctx.slots.inject('settings.section', () => ctx.slots.register(
    {
      name: 'settings.section',
      id: 'security-guard',
      order: 200,
      label: () => settingsNavLabel(),
      inject: () => ({}),
    },
    LangSection
  ))

  // The shield button in the session header. Registered while the
  // `showHeaderButton` preference is on; removed when it is turned off, so
  // toggling the setting in the DSH Settings shell shows or hides the button
  // without a reload. The register call runs through the caller's ctx (the
  // slot service binds the effect to the calling fiber), so both the initial
  // sync and the live preference/locale subscriptions land in this plugin's
  // fiber and are disposed with it.
  //
  // NOTE: no `inject` key on the seat entry on purpose. The slot renderer
  // treats `entry.inject` as a thunk and calls it (`inject(...)` in
  // runInject). Passing a plain object would throw `inject is not a
  // function` at render time and silently abdicate the entry (no button, no
  // error). GuardPanel reads the module-scope store, so it needs no injected
  // props.
  ctx.slots.inject('conversation.session.header.utilities', () => {
    let disposeEntry: (() => void) | null = null
    const sync = () => {
      const show = getShowHeader()
      if (show && disposeEntry === null) {
        disposeEntry = ctx.slots.register(
          {
            name: 'conversation.session.header.utilities',
            id: 'security-guard-review',
            order: 100,
            label: () => t('headerButton'),
          },
          GuardPanel
        )
      } else if (!show && disposeEntry !== null) {
        disposeEntry()
        disposeEntry = null
      }
    }
    const unsubPref = subscribePreference(sync)
    const unsubLoc = subscribeLocale(sync)
    sync()
    return [() => { unsubPref(); unsubLoc(); disposeEntry?.() }]
  })

  // The Security Review tab in the conversation view ring. Registered while
  // the `showSessionTab` preference is on; removed when it is turned off. The
  // register call runs through the caller's ctx (the slot service binds the
  // effect to the calling fiber), so both the initial sync and the live
  // preference/locale subscriptions land in this plugin's fiber and are
  // disposed with it.
  ctx.slots.inject('conversation.view', () => {
    let disposeEntry: (() => void) | null = null
    const sync = () => {
      const show = getShowTab()
      if (show && disposeEntry === null) {
        disposeEntry = ctx.slots.register(
          {
            name: 'conversation.view',
            id: 'security-guard',
            order: 20,
            label: () => t('viewTabGuard'),
          },
          GuardReviewView
        )
      } else if (!show && disposeEntry !== null) {
        disposeEntry()
        disposeEntry = null
      }
    }
    // Re-sync on preference changes (showTab toggles entry presence; language
    // changes re-register so the tab label follows the active locale without a
    // reload) and on DSH locale changes (auto mode follows it live).
    const unsubPref = subscribePreference(sync)
    const unsubLoc = subscribeLocale(sync)
    sync()
    return [() => { unsubPref(); unsubLoc(); disposeEntry?.() }]
  })
}

