const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WebSocket } = require('ws');

const testDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-test-'));
process.env.PORT = '0';
process.env.ORBIT_SECRET_FILE = path.join(testDirectory, 'secret');

const isWindows = process.platform === 'win32';
let server;
let ACCESS_CODE;
if (isWindows) ({ server, ACCESS_CODE } = require('../server'));
const maybeTest = isWindows ? test : test.skip;

test.before(async () => {
  if (!isWindows) return;
  if (!server.listening) await once(server, 'listening');
});

test.after(() => {
  if (!isWindows) return;
  return new Promise(resolve => server.close(resolve));
});

maybeTest('serves the remote access website and reports locked status', async () => {
  const { port } = server.address();
  const homepage = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(homepage.status, 200);
  assert.match(await homepage.text(), /<title>Orbit Remote/);
  const status = await fetch(`http://127.0.0.1:${port}/api/status`).then(response => response.json());
  assert.equal(status.authenticated, false);
  assert.ok(status.screen.width > 0);
});

maybeTest('rejects an incorrect code and authenticates the private code', async () => {
  const { port } = server.address();
  const bad = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code: 'WRONGCODE' })
  });
  assert.equal(bad.status, 401);

  const good = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code: ACCESS_CODE })
  });
  assert.equal(good.status, 200);
  assert.match(good.headers.get('set-cookie'), /orbit_session=/);
});

maybeTest('opens the desktop socket with a valid authenticated session', async () => {
  const { port } = server.address();
  const login = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code: ACCESS_CODE })
  });
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const socket = new WebSocket(`ws://127.0.0.1:${port}/remote`, { headers: { Cookie: cookie } });
  const welcomeMessage = once(socket, 'message');
  await once(socket, 'open');
  const [message] = await welcomeMessage;
  const welcome = JSON.parse(message.toString());
  assert.equal(welcome.type, 'welcome');
  socket.close();
  await once(socket, 'close');
});
