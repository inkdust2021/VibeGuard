// Regression checks for settings responses arriving after the user changes pages.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../internal/admin/static/index.html'), 'utf8');
const source = html.slice(html.indexOf('function renderSettingsMeta()'), html.indexOf('async function renderSettings()'));
const settings = {
  proxy: { websocket_redaction_beta: false },
  cleanup: {
    log: { enabled: true, interval: '24h', max_size_mb: 10, max_backups: 3 },
    session_wal: { enabled: true, interval: '1h' }
  }
};

async function main() {
  let elements = {};
  const messages = [];
  let finishSave;
  const context = vm.createContext({
    state: { settings },
    document: { getElementById: id => elements[id] || null },
    api: { post: () => new Promise(resolve => { finishSave = resolve; }) },
    t: key => key,
    toast: (message, kind) => messages.push({ message, kind })
  });
  vm.runInContext(source, context);
  assert.doesNotThrow(() => context.renderSettingsMeta(), 'GET response after navigation');
  elements = {
    'cleanup-log-enabled': { checked: true },
    'cleanup-log-interval': { value: '2h' },
    'cleanup-log-size': { value: '10' },
    'cleanup-log-backups': { value: '3' },
    'cleanup-wal-enabled': { checked: false },
    'cleanup-wal-interval': { value: '1h' },
    'cleanup-save': { disabled: false }
  };
  const save = context.saveCleanupSettings({ preventDefault() {} });
  elements = {}; // The route changes while the POST is pending.
  finishSave(settings);
  await save;
  assert.equal(messages.length, 1);
  assert.equal(messages[0].message, 'settings.updated');
  assert.notEqual(messages[0].kind, 'error', 'successful save must not report failure after navigation');
  console.log('Cleanup UI navigation checks passed');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
