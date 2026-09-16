// node:test suite for the platform-adaptive rule catalogue (runs against lib/).
// Usage: npm run build && node --test tools/
import test from 'node:test'
import assert from 'node:assert/strict'
import { detectPlatform, resolvePlatform } from '../lib/platform.js'
import { buildThreatCatalog, activeThreatCatalog, setActiveThreatCatalog } from '../lib/threat-catalog.js'
import { deriveToolCallFeatures } from '../lib/features.js'
import { deriveCommandThreatFeatures } from '../lib/command-threats.js'

const LINUX = buildThreatCatalog('linux')
const WIN32 = buildThreatCatalog('win32')
const DARWIN = buildThreatCatalog('darwin')

function withPlatform(platform, fn) {
  setActiveThreatCatalog(platform)
  try {
    return fn()
  } finally {
    setActiveThreatCatalog('linux')
  }
}

test('platform: auto follows the host; explicit values win', () => {
  const host = detectPlatform()
  assert.ok(['win32', 'linux', 'darwin'].includes(host))
  assert.equal(resolvePlatform('auto'), host)
  assert.equal(resolvePlatform(undefined), host)
  assert.equal(resolvePlatform('win32'), 'win32')
  assert.equal(resolvePlatform('linux'), 'linux')
  assert.equal(resolvePlatform('darwin'), 'darwin')
})

test('platform: DSH_GUARD_PLATFORM overrides auto, explicit config still wins', () => {
  const prev = process.env.DSH_GUARD_PLATFORM
  process.env.DSH_GUARD_PLATFORM = 'darwin'
  try {
    assert.equal(resolvePlatform('auto'), 'darwin')
    assert.equal(resolvePlatform(undefined), 'darwin')
    assert.equal(resolvePlatform('linux'), 'linux')
  } finally {
    if (prev === undefined) delete process.env.DSH_GUARD_PLATFORM
    else process.env.DSH_GUARD_PLATFORM = prev
  }
})

test('platform: POSIX families are absent from the win32 catalogue and vice versa', () => {
  // rm-compact rows are POSIX only.
  assert.ok(LINUX.highRiskCompact.length > 0)
  assert.equal(WIN32.highRiskCompact.length, 0)
  // /etc protected tokens are POSIX only; the Windows hosts file is win32 only.
  assert.ok(LINUX.protectedPathTokens.includes('/etc/passwd'))
  assert.ok(!WIN32.protectedPathTokens.includes('/etc/passwd'))
  assert.ok(WIN32.protectedPathTokens.includes('drivers\\etc\\hosts'))
  assert.ok(!LINUX.protectedPathTokens.includes('drivers\\etc\\hosts'))
  // Cross-platform tokens survive on both.
  assert.ok(LINUX.protectedPathTokens.includes('.ssh'))
  assert.ok(WIN32.protectedPathTokens.includes('.ssh'))
})

test('platform: darwin layers the POSIX set plus macOS rows', () => {
  // POSIX rows survive…
  assert.ok(DARWIN.highRisk.some((re) => re.test('rm -rf /')))
  assert.ok(DARWIN.highRiskCompact.length > 0)
  assert.ok(DARWIN.protectedPathTokens.includes('/etc/passwd'))
  // …plus macOS-only rows.
  assert.ok(DARWIN.highRisk.some((re) => re.test('diskutil eraseDisk APFS /dev/disk2')))
  assert.ok(DARWIN.highRisk.some((re) => re.test('csrutil disable')))
  assert.ok(!LINUX.highRisk.some((re) => re.test('diskutil eraseDisk APFS /dev/disk2')))
})

test('platform: arming win32 flips native detection on and POSIX detection off', () => {
  withPlatform('win32', () => {
    assert.equal(activeThreatCatalog(), WIN32)
    assert.equal(deriveToolCallFeatures({ command: 'format c:' }, {}).highRisk, true)
    assert.equal(deriveToolCallFeatures({ command: 'vssadmin delete shadows /all' }, {}).highRisk, true)
    assert.equal(deriveToolCallFeatures({ command: 'rm -rf /' }, {}).highRisk, undefined)
    assert.equal(deriveCommandThreatFeatures({ command: 'net localgroup administrators x /add' }).privEsc, 'block')
    assert.equal(deriveCommandThreatFeatures({ command: 'chmod -R 777 /srv' }).privEsc, undefined)
  })
})

test('platform: arming darwin detects macOS-only actions', () => {
  withPlatform('darwin', () => {
    assert.equal(activeThreatCatalog(), DARWIN)
    assert.equal(deriveToolCallFeatures({ command: 'osascript -e \'do shell script "id"\'' }, {}).highRisk, true)
    assert.equal(deriveCommandThreatFeatures({ command: 'csrutil disable' }).privEsc, 'block')
  })
})

test('platform (win32): backslash paths are protected and Remove-Item counts as a delete', () => {
  withPlatform('win32', () => {
    // Backslash path candidates must reach the protected-token scan.
    const hosts = deriveToolCallFeatures({ command: 'Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts' }, {})
    assert.equal(hosts.protectedPathHit, 'C:\\Windows\\System32\\drivers\\etc\\hosts')
    // Remove-Item is a delete verb (case-insensitively) and yields a target.
    const del = deriveToolCallFeatures(
      { command: 'Remove-Item -Path C:\\Windows\\System32\\drivers\\etc\\hosts -Force' },
      { workspaceRoot: 'C:\\Users\\someone\\workspace' },
    )
    assert.ok(Array.isArray(del.deleteTargets) && del.deleteTargets.length >= 1)
    assert.equal(del.protectedPathHit, 'C:\\Windows\\System32\\drivers\\etc\\hosts')
  })
})

test('platform: linux (default) keeps the historical POSIX behavior', () => {
  assert.equal(activeThreatCatalog(), LINUX)
  assert.equal(deriveToolCallFeatures({ command: 'rm -rf /' }, {}).highRisk, true)
  assert.equal(deriveCommandThreatFeatures({ command: 'chmod u+s /tmp/x' }).privEsc, 'block')
  assert.equal(deriveToolCallFeatures({ command: 'format c:' }, {}).highRisk, undefined)
})
