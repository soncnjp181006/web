/**
 * Redis cache wrapper with in-memory fallback (works on Render Key Value, rediss://).
 * Used by the rate limiter ([VULN #52]) and cache demos.
 */
const state = { client: null, connecting: null, mem: new Map(), mode: "memory" };

async function getClient() {
  if (state.client) return state.client;
  if (state.connecting) return state.connecting;
  const url = process.env.REDIS_URL;
  if (!url) return null;
  state.connecting = (async () => {
    try {
      const { createClient } = require("redis");
      const c = createClient({ url, socket: { reconnectStrategy: (retries) => (retries > 3 ? new Error("stop") : 1000) } });
      c.on("error", () => {});
      await c.connect();
      state.client = c;
      state.mode = "redis";
      console.log("[redis] connected");
      return c;
    } catch (e) {
      console.log("[redis] unavailable, using in-memory fallback:", e.message);
      return null;
    } finally {
      state.connecting = null;
    }
  })();
  return state.connecting;
}

function memIncrWindow(key, windowMs) {
  const now = Date.now();
  const cur = state.mem.get(key);
  if (!cur || cur.resetAt <= now) {
    state.mem.set(key, { count: 1, resetAt: now + windowMs });
    return 1;
  }
  cur.count += 1;
  return cur.count;
}

async function incrWindow(key, windowMs) {
  const c = await getClient();
  if (!c) return memIncrWindow(key, windowMs);
  try {
    const n = await c.incr(key);
    if (n === 1) await c.pexpire(key, windowMs);
    return n;
  } catch {
    return memIncrWindow(key, windowMs);
  }
}

async function get(key) {
  const c = await getClient();
  if (!c) {
    const cur = state.mem.get(key);
    return cur && cur.resetAt > Date.now() ? cur.value : null;
  }
  try {
    return await c.get(key);
  } catch {
    return null;
  }
}

async function set(key, value, ttlMs = 0) {
  const c = await getClient();
  if (!c) {
    state.mem.set(key, { value, resetAt: Date.now() + ttlMs });
    return true;
  }
  try {
    if (ttlMs > 0) await c.set(key, value, { PX: ttlMs });
    else await c.set(key, value);
    return true;
  } catch {
    return false;
  }
}

module.exports = (container) => ({ getClient, incrWindow, get, set, mode: () => state.mode });
