const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { spawn, spawnSync } = require('child_process');
const { WebSocketServer, WebSocket } = require('ws');
const sharp = require('sharp');
const robot = require('@jitsi/robotjs');
const ffmpegPath = require('ffmpeg-static');

const PORT = Number(process.env.PORT || 4173);
const HOST = process.env.HOST || '127.0.0.1';
const PUBLIC_DIR = path.join(__dirname, 'public');
const SECRET_FILE = process.env.ORBIT_SECRET_FILE || path.join(__dirname, '.orbit-secret');
const DISPLAY_SCRIPT = path.join(__dirname, 'scripts', 'display-resolution.ps1');
const SESSION_TTL = 12 * 60 * 60 * 1000;
const sessions = new Map();
const loginAttempts = new Map();
const clients = new Set();
let captureRunning = false;
let streamSettings = { fps: 7, width: 1600, quality: 62 };
let activeController = null;
let videoProcess = null;
let videoBuffer = Buffer.alloc(0);
let videoFrameId = 0;
let videoGeneration = 0;
let videoSettings = null;
let videoStats = { frames: 0, bytes: 0, startedAt: Date.now() };
let videoRecoveryTimer = null;
let lastVideoRecovery = 0;
let videoOutputPaused = false;
// At 60 FPS this is a hard 200 ms ceiling, not an unbounded transport queue.
const MAX_FRAMES_IN_FLIGHT = 12;
const MAX_SOCKET_BUFFER = 1024 * 1024;
let displayChangeSequence = Promise.resolve();
let activeDisplayKey = null;
let displayRestoreTimer = null;

robot.setMouseDelay(0);
robot.setKeyboardDelay(2);

function readOriginalDisplayMode() {
  const fallback = { ...robot.getScreenSize(), refresh: 60 };
  try {
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', DISPLAY_SCRIPT, '-Current'], { encoding: 'utf8', windowsHide: true, timeout: 10000 });
    return result.status === 0 ? JSON.parse(result.stdout.trim()) : fallback;
  } catch {
    return fallback;
  }
}

const originalDisplayMode = readOriginalDisplayMode();

function loadAccessCode() {
  if (fs.existsSync(SECRET_FILE)) return fs.readFileSync(SECRET_FILE, 'utf8').trim();
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(10);
  const code = Array.from(bytes.slice(0, 10), byte => alphabet[byte % alphabet.length]).join('');
  fs.writeFileSync(SECRET_FILE, code, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  return code;
}

const ACCESS_CODE = loadAccessCode();

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const entries = [];
  for (const part of header.split(';')) {
    if (!part) continue;
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    const rawValue = part.slice(index + 1).trim();
    try { entries.push([name, decodeURIComponent(rawValue)]); } catch { entries.push([name, rawValue]); }
  }
  return Object.fromEntries(entries);
}

function getSession(req) {
  const token = parseCookies(req).orbit_session;
  const session = token && sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (token) sessions.delete(token);
    return null;
  }
  session.expiresAt = Date.now() + SESSION_TTL;
  return session;
}

function json(res, status, payload, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  });
  res.end(JSON.stringify(payload));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let aborted = false;
    req.on('data', chunk => {
      if (aborted) return;
      body += chunk;
      if (body.length > 4096) {
        aborted = true;
        reject(new Error('Body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (aborted) return;
      try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
    req.on('close', () => {
      if (!aborted && body.length > 4096) reject(new Error('Body too large'));
    });
  });
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function clientKey(req) {
  return req.headers['tailscale-user-login'] || req.socket.remoteAddress || 'unknown';
}

function isRateLimited(req) {
  const key = clientKey(req);
  const record = loginAttempts.get(key);
  if (!record) return false;
  if (record.resetAt < Date.now()) {
    loginAttempts.delete(key);
    return false;
  }
  return record.count >= 8;
}

function recordFailure(req) {
  const key = clientKey(req);
  const current = loginAttempts.get(key);
  loginAttempts.set(key, current && current.resetAt > Date.now()
    ? { count: current.count + 1, resetAt: current.resetAt }
    : { count: 1, resetAt: Date.now() + 15 * 60 * 1000 });
}

function securityHeaders() {
  return {
    'Content-Security-Policy': "default-src 'self'; img-src 'self' blob: data:; connect-src 'self' ws: wss:; style-src 'self'; script-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
  };
}

async function handleApi(req, res, pathname) {
  if (pathname === '/api/login' && req.method === 'POST') {
    if (isRateLimited(req)) return json(res, 429, { error: 'Too many attempts. Try again later.' });
    let body;
    try { body = await readJson(req); } catch { return json(res, 400, { error: 'Invalid request.' }); }
    if (!safeEqual(String(body.code || '').toUpperCase(), ACCESS_CODE)) {
      recordFailure(req);
      return json(res, 401, { error: 'That access code is not correct.' });
    }
    loginAttempts.delete(clientKey(req));
    const token = crypto.randomBytes(32).toString('base64url');
    sessions.set(token, { createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL, identity: req.headers['tailscale-user-login'] || 'local user' });
    const isSecure = req.headers['x-forwarded-proto'] === 'https';
    const cookie = `orbit_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}${isSecure ? '; Secure' : ''}`;
    return json(res, 200, { ok: true }, { 'Set-Cookie': cookie });
  }

  if (pathname === '/api/status' && req.method === 'GET') {
    const session = getSession(req);
    const screen = robot.getScreenSize();
    return json(res, 200, {
      authenticated: Boolean(session),
      computer: os.hostname(),
      platform: 'Windows',
      screen,
      connected: clients.size,
      controller: Boolean(activeController)
    });
  }

  if (pathname === '/api/logout' && req.method === 'POST') {
    const token = parseCookies(req).orbit_session;
    if (token) sessions.delete(token);
    return json(res, 200, { ok: true }, { 'Set-Cookie': 'orbit_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }

  return json(res, 404, { error: 'Not found.' });
}

const server = http.createServer(async (req, res) => {
  let pathname = '/';
  try {
    pathname = decodeURIComponent((req.url || '/').split('?')[0]);
  } catch {
    res.writeHead(400, securityHeaders()).end('Bad request');
    return;
  }
  if (pathname.startsWith('/api/')) return handleApi(req, res, pathname);

  const requested = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const filePath = path.resolve(PUBLIC_DIR, requested);
  if (filePath !== PUBLIC_DIR && !filePath.startsWith(`${PUBLIC_DIR}${path.sep}`)) {
    res.writeHead(403, securityHeaders()).end('Forbidden');
    return;
  }
  fs.readFile(filePath, (error, data) => {
    if (error) {
      res.writeHead(404, securityHeaders()).end('Not found');
      return;
    }
    res.writeHead(200, {
      ...securityHeaders(),
      'Content-Type': mimeTypes[path.extname(filePath)] || 'application/octet-stream',
      'Cache-Control': ['.html', '.css', '.js'].includes(path.extname(filePath)) ? 'no-cache' : 'public, max-age=3600'
    });
    res.end(data);
  });
});

const wss = new WebSocketServer({ noServer: true, maxPayload: 32 * 1024 });

server.on('upgrade', (req, socket, head) => {
  if ((req.url || '').split('?')[0] !== '/remote' || !getSession(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});

function sendJson(ws, payload) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
}

const keyMap = {
  Enter: 'enter', Tab: 'tab', Escape: 'escape', Backspace: 'backspace', Delete: 'delete',
  ArrowUp: 'up', ArrowDown: 'down', ArrowLeft: 'left', ArrowRight: 'right',
  Home: 'home', End: 'end', PageUp: 'pageup', PageDown: 'pagedown', Insert: 'insert',
  Space: 'space', CapsLock: 'capslock', PrintScreen: 'printscreen',
  F1: 'f1', F2: 'f2', F3: 'f3', F4: 'f4', F5: 'f5', F6: 'f6',
  F7: 'f7', F8: 'f8', F9: 'f9', F10: 'f10', F11: 'f11', F12: 'f12'
};

function robotKey(event) {
  if (/^Key[A-Z]$/.test(event.code)) return event.code.slice(3).toLowerCase();
  if (/^Digit[0-9]$/.test(event.code)) return event.code.slice(5);
  if (/^Numpad[0-9]$/.test(event.code)) return `numpad_${event.code.slice(6)}`;
  return keyMap[event.code] || keyMap[event.key] || (event.key?.length === 1 ? event.key.toLowerCase() : null);
}

function handleInput(ws, input) {
  if (ws !== activeController || !input || typeof input !== 'object') return;
  const screen = robot.getScreenSize();
  try {
    if (input.type === 'move') {
      const x = Math.max(0, Math.min(screen.width - 1, Math.round(Number(input.x) * screen.width)));
      const y = Math.max(0, Math.min(screen.height - 1, Math.round(Number(input.y) * screen.height)));
      robot.moveMouse(x, y);
    } else if (input.type === 'button' && ['left', 'middle', 'right'].includes(input.button)) {
      robot.mouseToggle(input.down ? 'down' : 'up', input.button);
    } else if (input.type === 'wheel') {
      robot.scrollMouse(Math.round(Number(input.x) || 0), Math.round(-(Number(input.y) || 0)));
    } else if (input.type === 'key') {
      const key = robotKey(input);
      if (!key) return;
      const modifiers = [];
      if (input.ctrl) modifiers.push('control');
      if (input.alt) modifiers.push('alt');
      if (input.shift) modifiers.push('shift');
      if (input.meta) modifiers.push('command');
      robot.keyTap(key, modifiers);
    }
  } catch (error) {
    sendJson(ws, { type: 'input-error', message: 'That input is not supported.' });
  }
}

function controllerChanged() {
  for (const client of clients) sendJson(client, { type: 'control', enabled: client === activeController });
}

function requestedDisplayMode(message) {
  const preset = String(message.resolution || 'auto');
  if (preset === 'native') return { ...originalDisplayMode, exact: true, key: `native:${originalDisplayMode.width}x${originalDisplayMode.height}` };
  const manual = /^(\d{3,4})x(\d{3,4})$/.exec(preset);
  if (manual) {
    const width = Number(manual[1]);
    const height = Number(manual[2]);
    return { width, height, refresh: 60, exact: true, key: `manual:${width}x${height}` };
  }

  let width = Math.max(640, Number(message.clientWidth) || 1280);
  let height = Math.max(480, Number(message.clientHeight) || 720);
  const scale = Math.min(1, 1920 / width, 1440 / height);
  width = Math.round(width * scale);
  height = Math.round(height * scale);
  const ratioBucket = Math.round((width / height) * 20) / 20;
  return { width, height, refresh: 60, exact: false, key: `auto:${ratioBucket}:${Math.round(width / 160)}` };
}

function runDisplayChange(target) {
  const operation = displayChangeSequence.then(() => new Promise((resolve, reject) => {
    const args = [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', DISPLAY_SCRIPT,
      '-Width', String(target.width), '-Height', String(target.height), '-RefreshRate', String(target.refresh || 60)
    ];
    if (target.exact) args.push('-Exact');
    const child = spawn('powershell.exe', args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', data => { stdout += data.toString(); });
    child.stderr.on('data', data => { stderr += data.toString(); });
    child.on('error', reject);
    child.on('exit', code => {
      if (code !== 0) return reject(new Error(stderr.trim() || 'Windows could not change the display resolution.'));
      try { resolve(JSON.parse(stdout.trim())); } catch { reject(new Error('Windows returned an invalid display result.')); }
    });
  }));
  displayChangeSequence = operation.catch(() => null);
  return operation;
}

async function applyClientDisplay(ws, message) {
  if (ws !== activeController) return robot.getScreenSize();
  const target = requestedDisplayMode(message);
  if (activeDisplayKey === target.key) return robot.getScreenSize();
  stopVideoEncoder();
  try {
    const result = await runDisplayChange(target);
    activeDisplayKey = target.key;
    await new Promise(resolve => setTimeout(resolve, 250));
    const screen = robot.getScreenSize();
    const payload = { type: 'display-status', width: screen.width, height: screen.height, refresh: result.refresh };
    for (const client of clients) sendJson(client, payload);
    return screen;
  } catch (error) {
    sendJson(ws, { type: 'display-error', message: error.message });
    return robot.getScreenSize();
  }
}

wss.on('connection', (ws) => {
  if (displayRestoreTimer) {
    clearTimeout(displayRestoreTimer);
    displayRestoreTimer = null;
  }
  clients.add(ws);
  ws.streamMode = 'pending';
  ws.videoReady = false;
  ws.framesInFlight = 0;
  ws.lastSentFrame = -1;
  ws.lastAckFrame = -1;
  ws.videoGeneration = 0;
  ws.jpegAwaitingAck = false;
  if (!activeController) activeController = ws;
  sendJson(ws, {
    type: 'welcome',
    computer: os.hostname(),
    screen: robot.getScreenSize(),
    control: ws === activeController,
    preferredTransport: 'h264-webcodecs'
  });
  controllerChanged();

  ws.on('message', async (buffer, isBinary) => {
    if (isBinary) return;
    let message;
    try { message = JSON.parse(buffer.toString()); } catch { return; }
    if (message.type === 'input') handleInput(ws, message.input);
    if (message.type === 'latency-ping') sendJson(ws, { type: 'latency-pong', id: message.id });
    if (message.type === 'frame-ack' && Number(message.generation) === ws.videoGeneration) {
      const frameId = Number(message.frameId);
      if (Number.isInteger(frameId) && frameId >= ws.lastAckFrame && frameId <= ws.lastSentFrame) {
        ws.lastAckFrame = frameId;
        ws.framesInFlight = Math.max(0, ws.lastSentFrame - frameId);
        resumeVideoOutput();
      }
    }
    if (message.type === 'jpeg-ack') ws.jpegAwaitingAck = false;
    if (message.type === 'client-config') {
      ws.lastClientConfig = message;
      const requestVersion = (ws.configVersion || 0) + 1;
      ws.configVersion = requestVersion;
      const supportsH264 = Array.isArray(message.codecs) && message.codecs.includes('h264-webcodecs');
      ws.streamMode = supportsH264 ? 'h264' : 'jpeg';
      const screen = await applyClientDisplay(ws, message);
      if (ws.readyState !== WebSocket.OPEN || ws.configVersion !== requestVersion) return;
      if (supportsH264) {
        const requestedWidth = Math.max(640, Math.min(2560, Number(message.width) || 1280));
        const width = Math.max(640, Math.round(requestedWidth / 16) * 16);
        const height = Math.max(272, Math.round((width * screen.height / screen.width) / 2) * 2);
        const settings = {
          width,
          height,
          fps: 60,
          bitrate: Math.max(4, Math.min(50, Number(message.bitrate) || 16))
        };
        if (ws === activeController || !videoSettings) startVideoEncoder(settings);
        else sendVideoConfig(ws);
      } else {
        streamSettings = {
          fps: 10,
          width: Math.max(720, Math.min(1600, Number(message.width) || 1280)),
          quality: 68
        };
        if (![...clients].some(client => client.streamMode === 'h264')) stopVideoEncoder();
        startJpegCapture();
      }
    }
    if (message.type === 'settings') {
      streamSettings = {
        fps: Math.max(2, Math.min(10, Number(message.fps) || 7)),
        width: Math.max(720, Math.min(1920, Number(message.width) || 1600)),
        quality: Math.max(35, Math.min(82, Number(message.quality) || 62))
      };
    }
    if (message.type === 'resync') {
      ws.videoReady = false;
      requestVideoRecovery();
    }
    if (message.type === 'request-control' && !activeController) {
      activeController = ws;
      controllerChanged();
    }
    if (message.type === 'release-control' && activeController === ws) {
      activeController = null;
      controllerChanged();
    }
  });

  ws.on('close', () => {
    clients.delete(ws);
    if (activeController === ws) activeController = clients.values().next().value || null;
    if (![...clients].some(client => client.streamMode === 'h264')) stopVideoEncoder();
    if (clients.size === 0 && activeDisplayKey && !activeDisplayKey.startsWith('native:')) {
      displayRestoreTimer = setTimeout(() => {
        displayRestoreTimer = null;
        if (clients.size !== 0) return;
        const restore = { ...originalDisplayMode, exact: true };
        runDisplayChange(restore).then(() => { activeDisplayKey = `native:${originalDisplayMode.width}x${originalDisplayMode.height}`; }).catch(() => {});
      }, 5000);
      displayRestoreTimer.unref?.();
    }
    controllerChanged();
  });
});

function sameVideoSettings(left, right) {
  return left && right && left.width === right.width && left.height === right.height && left.fps === right.fps && left.bitrate === right.bitrate;
}

function sendVideoConfig(ws) {
  if (videoSettings) {
    ws.videoGeneration = videoGeneration;
    sendJson(ws, { type: 'stream-config', codec: 'avc1.640033', generation: videoGeneration, ...videoSettings });
  }
}

function stopVideoEncoder() {
  if (videoProcess) {
    videoProcess.removeAllListeners('exit');
    videoProcess.kill();
    videoProcess = null;
  }
  videoBuffer = Buffer.alloc(0);
  videoSettings = null;
  videoOutputPaused = false;
}

function requestVideoRecovery() {
  if (!videoSettings || videoRecoveryTimer || ![...clients].some(client => client.streamMode === 'h264')) return;
  const delay = Math.max(0, 500 - (Date.now() - lastVideoRecovery));
  videoRecoveryTimer = setTimeout(() => {
    videoRecoveryTimer = null;
    if (!videoSettings || ![...clients].some(client => client.streamMode === 'h264')) return;
    const settings = { ...videoSettings };
    lastVideoRecovery = Date.now();
    startVideoEncoder(settings, true);
  }, delay);
}

function startVideoEncoder(settings, force = false) {
  if (!force && sameVideoSettings(settings, videoSettings) && videoProcess && !videoProcess.killed) {
    const needsFreshKey = [...clients].some(client => client.streamMode === 'h264' && client.videoGeneration !== videoGeneration);
    if (!needsFreshKey) return;
    force = true;
  }
  stopVideoEncoder();
  videoSettings = settings;
  videoFrameId = 0;
  videoGeneration++;
  for (const client of clients) {
    if (client.streamMode !== 'h264') continue;
    client.videoReady = false;
    client.framesInFlight = 0;
    client.lastSentFrame = -1;
    client.lastAckFrame = -1;
    client.videoGeneration = videoGeneration;
  }
  videoStats = { frames: 0, bytes: 0, startedAt: Date.now() };

  const bitrate = `${Math.round(settings.bitrate)}M`;
  const bufferSize = `${Math.max(500, Math.round(settings.bitrate * 1000 / 16))}K`;
  const filter = `ddagrab=output_idx=0:framerate=${settings.fps},hwdownload,format=bgra,scale=${settings.width}:${settings.height}:flags=bilinear,format=nv12`;
  const args = [
    '-hide_banner', '-loglevel', 'warning',
    '-filter_complex', filter,
    '-an', '-c:v', 'h264_amf',
    '-usage', 'ultralowlatency', '-quality', 'speed',
    '-rc', 'cbr', '-b:v', bitrate, '-maxrate', bitrate, '-bufsize', bufferSize,
    '-g', '15', '-max_b_frames', '0', '-aud', '1', '-header_spacing', '15',
    '-flags', 'low_delay', '-f', 'h264', 'pipe:1'
  ];

  const process = spawn(ffmpegPath, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  videoProcess = process;
  process.stdout.on('data', parseVideoData);
  process.stderr.on('data', data => {
    const text = data.toString();
    if (/error|failed|cannot/i.test(text)) console.error(`Video encoder: ${text.trim()}`);
  });
  process.on('exit', code => {
    if (videoProcess !== process) return;
    videoProcess = null;
    if ([...clients].some(client => client.streamMode === 'h264')) {
      for (const client of clients) if (client.streamMode === 'h264') sendJson(client, { type: 'capture-error', message: `Video encoder stopped (${code ?? 'unknown'}).` });
    }
  });

  for (const client of clients) if (client.streamMode === 'h264') sendVideoConfig(client);
}

function findAccessUnitDelimiters(buffer) {
  const positions = [];
  for (let index = 0; index < buffer.length - 5; index++) {
    let startLength = 0;
    if (buffer[index] === 0 && buffer[index + 1] === 0 && buffer[index + 2] === 1) startLength = 3;
    else if (buffer[index] === 0 && buffer[index + 1] === 0 && buffer[index + 2] === 0 && buffer[index + 3] === 1) startLength = 4;
    if (startLength && (buffer[index + startLength] & 0x1f) === 9) positions.push(index);
  }
  return positions;
}

function containsNalType(buffer, wantedType) {
  for (let index = 0; index < buffer.length - 5; index++) {
    let startLength = 0;
    if (buffer[index] === 0 && buffer[index + 1] === 0 && buffer[index + 2] === 1) startLength = 3;
    else if (buffer[index] === 0 && buffer[index + 1] === 0 && buffer[index + 2] === 0 && buffer[index + 3] === 1) startLength = 4;
    if (startLength && (buffer[index + startLength] & 0x1f) === wantedType) return true;
  }
  return false;
}

function parseVideoData(data) {
  videoBuffer = Buffer.concat([videoBuffer, data]);
  drainVideoBuffer();
}

function canAdvanceVideo() {
  const targets = [...clients].filter(client => client.streamMode === 'h264' && client.readyState === WebSocket.OPEN);
  return targets.length > 0 && targets.every(client => client.framesInFlight < MAX_FRAMES_IN_FLIGHT && client.bufferedAmount <= MAX_SOCKET_BUFFER);
}

function pauseVideoOutput() {
  if (videoOutputPaused || !videoProcess?.stdout) return;
  videoOutputPaused = true;
  videoProcess.stdout.pause();
}

function resumeVideoOutput() {
  if (videoOutputPaused) {
    if (!canAdvanceVideo()) return;
    videoOutputPaused = false;
    videoProcess?.stdout?.resume();
    return;
  }
  if (!videoProcess?.stdout || !canAdvanceVideo()) return;
  drainVideoBuffer();
  if (!canAdvanceVideo()) return;
  videoOutputPaused = false;
  videoProcess.stdout.resume();
}

function drainVideoBuffer() {
  while (videoSettings) {
    const delimiters = findAccessUnitDelimiters(videoBuffer);
    if (delimiters.length < 2) return;
    if (!canAdvanceVideo()) {
      pauseVideoOutput();
      return;
    }
    const accessUnit = videoBuffer.subarray(delimiters[0], delimiters[1]);
    videoBuffer = videoBuffer.subarray(delimiters[1]);
    broadcastVideoFrame(accessUnit);
  }
}

function broadcastVideoFrame(accessUnit) {
  if (!videoSettings || accessUnit.length < 8) return;
  const isKey = containsNalType(accessUnit, 5);
  const header = Buffer.allocUnsafe(16);
  header[0] = 2;
  header[1] = isKey ? 1 : 0;
  header.writeUInt16LE(videoSettings.width, 2);
  header.writeUInt16LE(videoSettings.height, 4);
  header.writeUInt16LE(videoSettings.fps, 6);
  const frameId = videoFrameId++ >>> 0;
  header.writeUInt32LE(frameId, 8);
  header.writeUInt32LE(accessUnit.length, 12);
  const packet = Buffer.concat([header, accessUnit]);

  for (const client of clients) {
    if (client.streamMode !== 'h264' || client.readyState !== WebSocket.OPEN) continue;
    if (!client.videoReady) {
      if (!isKey) continue;
      client.videoReady = true;
    }
    client.send(packet, { binary: true }, error => { if (!error) resumeVideoOutput(); });
    client.lastSentFrame = frameId;
    client.framesInFlight = Math.max(0, client.lastSentFrame - client.lastAckFrame);
  }
  videoStats.frames++;
  videoStats.bytes += packet.length;
  const elapsed = Date.now() - videoStats.startedAt;
  if (elapsed >= 2000) {
    const seconds = elapsed / 1000;
    const stats = {
      type: 'stats',
      fps: Number((videoStats.frames / seconds).toFixed(1)),
      mbps: Number(((videoStats.bytes * 8) / seconds / 1e6).toFixed(1)),
      viewers: clients.size,
      transport: 'H.264 / AMD AMF'
    };
    for (const client of clients) if (client.streamMode === 'h264') sendJson(client, stats);
    videoStats = { frames: 0, bytes: 0, startedAt: Date.now() };
  }
}

async function captureFrame() {
  const screen = robot.getScreenSize();
  const capture = robot.screen.capture(0, 0, screen.width, screen.height);
  return sharp(capture.image, { raw: { width: capture.width, height: capture.height, channels: 4 } })
    .removeAlpha()
    .recomb([[0, 0, 1], [0, 1, 0], [1, 0, 0]])
    .resize({ width: streamSettings.width, withoutEnlargement: true })
    .jpeg({ quality: streamSettings.quality })
    .toBuffer();
}

async function startJpegCapture() {
  if (captureRunning) return;
  captureRunning = true;
  let frames = 0;
  let bytes = 0;
  let statStarted = Date.now();
  while ([...clients].some(client => client.streamMode === 'jpeg')) {
    const started = Date.now();
    try {
      const frame = await captureFrame();
      frames++;
      bytes += frame.length;
      for (const client of clients) {
        if (client.streamMode === 'jpeg' && client.readyState === WebSocket.OPEN && !client.jpegAwaitingAck && client.bufferedAmount < 128 * 1024) {
          client.jpegAwaitingAck = true;
          client.send(frame, { binary: true });
        }
      }
      if (Date.now() - statStarted >= 2000) {
        const seconds = (Date.now() - statStarted) / 1000;
        for (const client of clients) if (client.streamMode === 'jpeg') sendJson(client, { type: 'stats', fps: Math.round(frames / seconds), mbps: Number(((bytes * 8) / seconds / 1e6).toFixed(1)), viewers: clients.size, transport: 'JPEG fallback' });
        frames = 0;
        bytes = 0;
        statStarted = Date.now();
      }
    } catch (error) {
      for (const client of clients) sendJson(client, { type: 'capture-error', message: 'Windows screen capture failed.' });
    }
    const wait = Math.max(0, (1000 / streamSettings.fps) - (Date.now() - started));
    await new Promise(resolve => setTimeout(resolve, wait));
  }
  captureRunning = false;
}

const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) if (session.expiresAt < now) sessions.delete(token);
  for (const [key, attempt] of loginAttempts) if (attempt.resetAt < now) loginAttempts.delete(key);
}, 10 * 60 * 1000);
cleanupTimer.unref();

server.listen(PORT, HOST, () => {
  const address = server.address();
  console.log(`\nOrbit Remote is running on ${os.hostname()}`);
  console.log(`Local address: http://${HOST}:${address.port}`);
  console.log('Access code: run "npm run code" to display the current access code');
  console.log('For browser access anywhere, run: npm run enable-anywhere\n');
});

module.exports = { server, ACCESS_CODE };
