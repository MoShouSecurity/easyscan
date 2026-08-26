// Run with: node --test frontend/tests/detail.test.cjs
// Execute the actual inline application script with a minimal DOM/Wails fixture.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../dist/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1]
  .replace(/\nrenderHome\(\);\nsetInterval\(poll, 2500\);/, '');

function fixture(overrides = {}) {
  const elements = new Map();
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, {innerHTML: '', style: {}, addEventListener() {}, classList: {add() {}, remove() {}, toggle() {}}});
      return elements.get(id);
    },
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener() {},
  };
  const calls = [];
  const go = {GetTask: async id => ({id, target: id, status: 'running'}), ...overrides};
  for (const name of ['Sites', 'Ports', 'Leaks', 'Directories', 'Subdomains', 'IPs']) {
    const key = 'List' + name + 'ByTask';
    go[key] ||= async (task, page) => {
      calls.push({name, task, page});
      return name === 'Ports' ? [{ip: '127.0.0.1', port: 443, protocol: 'tcp'}] : [];
    };
  }
  const context = vm.createContext({document, window: {go: {main: {App: go}}, runtime: {EventsOn() {}}}});
  vm.runInContext(script, context);
  return {calls, elements, run: code => vm.runInContext(code, context)};
}

test('opening a task resets all detail pages and displays existing ports', async () => {
  const f = fixture();
  f.run('detailTabPages = {ports: 2, sites: 3, ips: 4}; detailTabHasMore = {ports: true}');
  await f.run('openDetail("new-task")');
  assert.ok(f.calls.every(c => c.page === 0));
  assert.match(f.run('detailTabs.ports'), /443/);
  assert.equal(f.run('detailTabHasMore.ports'), false);
});

test('refreshing the same task preserves the selected page', async () => {
  const f = fixture();
  await f.run('openDetail("task")');
  f.run('detailTabPages.ports = 2');
  await f.run('renderDetail("task")');
  assert.equal(f.calls.filter(c => c.name === 'Ports').at(-1).page, 2);
});

test('late response from another task cannot overwrite the current task', async () => {
  let resolve;
  const delayed = new Promise(r => { resolve = r; });
  const f = fixture({GetTask: id => id === 'old-task' ? delayed : Promise.resolve({id, target: id, status: 'running'})});
  const old = f.run('openDetail("old-task")');
  await f.run('openDetail("new-task")');
  const current = f.elements.get('view').innerHTML;
  resolve({id: 'old-task', target: 'old-task', status: 'running'});
  await old;
  assert.equal(f.elements.get('view').innerHTML, current);
});

test('late error from another task cannot replace the current page', async () => {
  let reject;
  const delayed = new Promise((_, r) => { reject = r; });
  const f = fixture({GetTask: id => id === 'old-task' ? delayed : Promise.resolve({id, target: id, status: 'running'})});
  const old = f.run('openDetail("old-task")');
  await f.run('openDetail("new-task")');
  const current = f.elements.get('view').innerHTML;
  reject(new Error('old request failed'));
  await old;
  assert.equal(f.elements.get('view').innerHTML, current);
});

test('out-of-order pages keep the latest requested page', async () => {
  let resolve;
  const delayed = new Promise(r => { resolve = r; });
  let first = true;
  const f = fixture({ListPortsByTask: () => {
    if (first) { first = false; return delayed; }
    return Promise.resolve([{ip: '127.0.0.1', port: 8443}]);
  }});
  const old = f.run('openDetail("task")');
  f.run('detailTabPages.ports = 1');
  await f.run('renderDetail("task")');
  resolve([{ip: '127.0.0.1', port: 22}]);
  await old;
  assert.match(f.run('detailTabs.ports'), /8443/);
});

test('late polling result cannot send a different task back home', async () => {
  let resolve;
  const delayed = new Promise(r => { resolve = r; });
  let delay = false;
  const f = fixture({GetTask: id => delay && id === 'old-task' ? delayed : Promise.resolve({id, target: id, status: 'running'})});
  await f.run('openDetail("old-task")');
  delay = true;
  const pending = f.run('poll()');
  await f.run('openDetail("new-task")');
  resolve(null);
  await pending;
  assert.equal(f.run('state.view'), 'detail');
  assert.equal(f.run('state.taskID'), 'new-task');
  assert.equal(f.run('state.detailRendering'), false);
});

test('detail response after leaving the detail view is ignored', async () => {
  let resolve;
  const delayed = new Promise(r => { resolve = r; });
  const f = fixture({GetTask: () => delayed});
  const pending = f.run('openDetail("task")');
  f.run('state.view = "search"');
  f.elements.get('view').innerHTML = 'search results';
  resolve({id: 'task', target: 'task', status: 'running'});
  await pending;
  assert.equal(f.elements.get('view').innerHTML, 'search results');
});
