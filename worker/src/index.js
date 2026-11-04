// 「我很好」每日報平安 後端：D1 存紀錄，每 5 分鐘檢查誰今天還沒按，用 Web Push 通知。
const CODE_CHARS = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
const HM = /^([01]\d|2[0-3]):[0-5]\d$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const SECOND_ALERT_MS = 2 * 3600e3;
const KEEP_DAYS = 100;
const IDLE_DELETE_DAYS = 180;
// 免費方案每次排程只有 10 毫秒 CPU、50 次對外請求，一輪只做這麼多，做不完留給下一輪
const SWEEP_PUSHES = 15;
const SWEEP_ELDERS = 40;
const SWEEP_CHUNK = 5;
const MAX_PHONES = 30;
const CLEANUP_UTC_HOUR = 19; // 台北凌晨三點
const VAPID_REUSE_S = 6 * 3600;
const PUSH_HOSTS = [/^fcm\.googleapis\.com$/, /(^|\.)push\.apple\.com$/, /(^|\.)push\.services\.mozilla\.com$/, /(^|\.)notify\.windows\.com$/];

const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };

function newCode() {
  const r = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(r, (b) => CODE_CHARS[b % CODE_CHARS.length]).join('');
}
const cleanCode = (s) => String(s || '').toUpperCase().replace(/[^0-9A-Z]/g, '').slice(0, 12);

const tzFormats = new Map();
function localNow(tz, at = Date.now()) {
  let f = tzFormats.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-CA', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
    tzFormats.set(tz, f);
  }
  const p = Object.fromEntries(f.formatToParts(new Date(at)).map((x) => [x.type, x.value]));
  return { day: `${p.year}-${p.month}-${p.day}`, hm: `${p.hour}:${p.minute}` };
}
const addDays = (day, n) => new Date(Date.parse(day + 'T12:00:00Z') + n * 864e5).toISOString().slice(0, 10);
const validTz = (tz) => { try { localNow(tz); return true; } catch { return false; } };

// ---------- Web Push（RFC 8291 加密＋VAPID） ----------
async function hkdf(salt, ikm, info, len) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, len * 8));
}
async function encryptPayload(sub, text) {
  const uaPub = unb64u(sub.p256dh), auth = unb64u(sub.auth);
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, pair.privateKey, 256));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const ikm = await hkdf(auth, shared, concat(enc.encode('WebPush: info\0'), uaPub, asPub), 32);
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const body = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, concat(enc.encode(text), new Uint8Array([2]))));
  const head = new Uint8Array(21);
  head.set(salt); new DataView(head.buffer).setUint32(16, 4096); head[20] = 65;
  return concat(head, asPub, body);
}
const vapidCache = new Map();
async function vapidHeader(env, endpoint) {
  const aud = new URL(endpoint).origin, nowS = Math.floor(Date.now() / 1000);
  const cached = vapidCache.get(aud);
  if (cached && cached.until > nowS) return cached.value;
  const pub = unb64u(env.VAPID_PUBLIC);
  const jwk = { kty: 'EC', crv: 'P-256', x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)), d: env.VAPID_PRIVATE, ext: true };
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const data = b64u(enc.encode('{"typ":"JWT","alg":"ES256"}')) + '.' + b64u(enc.encode(JSON.stringify({ aud, exp: nowS + 12 * 3600, sub: env.SITE_URL })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(data));
  const value = `vapid t=${data}.${b64u(sig)}, k=${env.VAPID_PUBLIC}`;
  vapidCache.set(aud, { value, until: nowS + VAPID_REUSE_S });
  return value;
}
async function pushOne(env, sub, msg) {
  try {
    const res = await fetch(sub.endpoint, {
      method: 'POST',
      headers: { Authorization: await vapidHeader(env, sub.endpoint), 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '43200', Urgency: 'high' },
      body: await encryptPayload(sub, JSON.stringify(msg)),
    });
    if (res.status === 404 || res.status === 410) {
      await env.DB.prepare('DELETE FROM subs WHERE endpoint=?').bind(sub.endpoint).run();
      return false;
    }
    if (!res.ok) console.log('push failed', res.status, new URL(sub.endpoint).host, (await res.text()).slice(0, 200));
    return res.ok;
  } catch (e) { console.log('push error', String(e)); return false; }
}
async function pushRole(env, elderId, role, msg, onlyEach = false) {
  const q = 'SELECT * FROM subs WHERE elder_id=? AND role=?' + (onlyEach ? ' AND each_checkin=1' : '');
  const { results } = await env.DB.prepare(q).bind(elderId, role).all();
  const done = await Promise.all(results.map((s) => pushOne(env, s, msg)));
  return done.filter(Boolean).length;
}

// ---------- 共用 ----------
async function hit(env, key, limit, seconds) {
  const now = Date.now();
  const row = await env.DB.prepare(
    `INSERT INTO rate (k,n,exp) VALUES (?1,1,?2)
     ON CONFLICT(k) DO UPDATE SET n=CASE WHEN exp<?3 THEN 1 ELSE n+1 END, exp=CASE WHEN exp<?3 THEN ?2 ELSE exp END
     RETURNING n`).bind(key, now + seconds * 1000, now).first();
  return row.n <= limit;
}
async function ipKey(req) {
  const ip = req.headers.get('CF-Connecting-IP') || 'local';
  return b64u(await crypto.subtle.digest('SHA-256', enc.encode('ifc:' + ip))).slice(0, 16);
}
class Fail extends Error { constructor(status, msg) { super(msg); this.status = status; } }

async function findBy(env, req, column, code) {
  const c = cleanCode(code);
  const row = c.length === 12 ? await env.DB.prepare(`SELECT * FROM elders WHERE ${column}=?`).bind(c).first() : null;
  if (row) return row;
  if (!(await hit(env, 'bad:' + (await ipKey(req)), 30, 3600))) throw new Fail(429, '輸入錯誤太多次，請一小時後再試。');
  throw new Fail(404, '找不到這組配對碼，請再核對一次。');
}
const dailyState = (e, now, checked) => {
  if (checked) return 'ok';
  if (e.pause_until && now.day <= e.pause_until) return 'paused';
  if (now.day < e.start_day) return 'waiting';
  return now.hm >= e.deadline ? 'late' : 'waiting';
};
function checkSubscription(env, s) {
  if (!s || typeof s.endpoint !== 'string' || !s.keys || !s.keys.p256dh || !s.keys.auth) throw new Fail(400, '通知設定不完整。');
  const u = new URL(s.endpoint);
  const local = env.ALLOW_LOCAL_PUSH === '1' && u.hostname === '127.0.0.1';
  if (!local && (u.protocol !== 'https:' || !PUSH_HOSTS.some((r) => r.test(u.hostname)))) throw new Fail(400, '這個通知服務不支援。');
}

// ---------- API ----------
const actions = {
  async config(env) { return { vapid: env.VAPID_PUBLIC }; },

  async create(env, req, b) {
    if (!(await hit(env, 'new:' + (await ipKey(req)), 10, 86400))) throw new Fail(429, '今天建立太多組了，請明天再試。');
    const nickname = String(b.nickname || '').trim().slice(0, 12);
    if (!nickname) throw new Fail(400, '請填寫稱呼。');
    const tz = validTz(b.tz) ? b.tz : 'Asia/Taipei';
    if (!HM.test(b.remindAt) || !HM.test(b.deadline) || b.remindAt >= b.deadline) throw new Fail(400, '通知家人的時間要比提醒長輩的時間晚。');
    const now = localNow(tz), t = Date.now();
    const start = now.hm >= b.deadline ? addDays(now.day, 1) : now.day;
    const elder = newCode(), family = newCode();
    await env.DB.prepare('INSERT INTO elders (elder_code,family_code,nickname,tz,remind_at,deadline,start_day,created_at,last_seen) VALUES (?,?,?,?,?,?,?,?,?)')
      .bind(elder, family, nickname, tz, b.remindAt, b.deadline, start, t, t).run();
    return { elderCode: elder, familyCode: family, nickname };
  },

  async elder(env, req, b) {
    const e = await findBy(env, req, 'elder_code', b.code);
    const now = localNow(e.tz);
    const c = await env.DB.prepare('SELECT at FROM checkins WHERE elder_id=? AND day=?').bind(e.id, now.day).first();
    return { nickname: e.nickname, tz: e.tz, today: now.day, checkedAt: c ? c.at : null, remindAt: e.remind_at, deadline: e.deadline, callAt: e.call_at };
  },

  async checkin(env, req, b, ctx) {
    const e = await findBy(env, req, 'elder_code', b.code);
    const t = Date.now();
    const at = Number.isFinite(b.at) && b.at <= t && b.at > t - 36 * 3600e3 ? b.at : t;
    const { day } = localNow(e.tz, at), today = localNow(e.tz, t).day;
    const r = await env.DB.prepare('INSERT OR IGNORE INTO checkins (elder_id,day,at) VALUES (?,?,?)').bind(e.id, day, at).run();
    if (r.meta.changes > 0) {
      await env.DB.prepare("UPDATE elders SET last_seen=?, last_day=MAX(COALESCE(last_day,''),?) WHERE id=?").bind(t, day, e.id).run();
      if (day === today) {
        // 已經發過「還沒按」的話，要讓所有家人知道沒事了；平常只通知有勾「每次都通知」的人
        const msg = { title: `${e.nickname}報平安了`, body: `${e.nickname}今天按了「我很好」。`, tag: 'late-' + e.id };
        ctx.waitUntil(pushRole(env, e.id, 'family', msg, e.alert_day !== today));
      }
    }
    const c = await env.DB.prepare('SELECT at FROM checkins WHERE elder_id=? AND day=?').bind(e.id, today).first();
    return { today, checkedAt: c ? c.at : null };
  },

  async callMe(env, req, b) {
    const e = await findBy(env, req, 'elder_code', b.code);
    if (!(await hit(env, 'call:' + e.id, 5, 86400))) throw new Fail(429, '今天已經請家人打電話好幾次了。');
    await env.DB.prepare('UPDATE elders SET call_at=? WHERE id=?').bind(Date.now(), e.id).run();
    const sent = await pushRole(env, e.id, 'family', { title: `${e.nickname}想接到您的電話`, body: `${e.nickname}按了「請家人打電話給我」，有空打個電話吧。`, tag: 'call-' + e.id });
    return { sent };
  },

  async family(env, req, b) {
    const e = await findBy(env, req, 'family_code', b.code);
    const now = localNow(e.tz), t = Date.now();
    const { results } = await env.DB.prepare('SELECT day,at FROM checkins WHERE elder_id=? AND day>=? ORDER BY day').bind(e.id, addDays(now.day, -KEEP_DAYS)).all();
    const subs = await env.DB.prepare('SELECT role,COUNT(*) n FROM subs WHERE elder_id=? GROUP BY role').bind(e.id).all();
    const count = Object.fromEntries(subs.results.map((r) => [r.role, r.n]));
    await env.DB.prepare('UPDATE elders SET last_seen=? WHERE id=?').bind(t, e.id).run();
    const today = results.find((r) => r.day === now.day);
    return {
      nickname: e.nickname, tz: e.tz, today: now.day, remindAt: e.remind_at, deadline: e.deadline, pauseUntil: e.pause_until,
      startDay: e.start_day, createdDay: localNow(e.tz, e.created_at).day, state: dailyState(e, now, !!today), checkedAt: today ? today.at : null, days: results,
      elderCode: e.elder_code, callAt: e.call_at, familyDevices: count.family || 0, elderDevices: count.elder || 0,
      alert: e.alert_day === now.day ? { count: e.alert_count, at: e.alert_at, sent: e.alert_sent } : null,
    };
  },

  async settings(env, req, b) {
    const e = await findBy(env, req, 'family_code', b.code);
    const nickname = b.nickname === undefined ? e.nickname : String(b.nickname).trim().slice(0, 12);
    const remind = b.remindAt === undefined ? e.remind_at : b.remindAt;
    const deadline = b.deadline === undefined ? e.deadline : b.deadline;
    if (!nickname) throw new Fail(400, '請填寫稱呼。');
    if (!HM.test(remind) || !HM.test(deadline) || remind >= deadline) throw new Fail(400, '通知家人的時間要比提醒長輩的時間晚。');
    let pause = e.pause_until;
    if (b.pauseUntil !== undefined) {
      pause = b.pauseUntil || null;
      const today = localNow(e.tz).day;
      if (pause && (!DAY.test(pause) || pause < today || pause > addDays(today, 90))) throw new Fail(400, '暫停日期要在今天到 90 天內。');
    }
    await env.DB.prepare('UPDATE elders SET nickname=?,remind_at=?,deadline=?,pause_until=? WHERE id=?').bind(nickname, remind, deadline, pause, e.id).run();
    return { ok: true };
  },

  async remove(env, req, b) {
    const e = await findBy(env, req, 'family_code', b.code);
    await env.DB.batch([
      env.DB.prepare('DELETE FROM checkins WHERE elder_id=?').bind(e.id),
      env.DB.prepare('DELETE FROM subs WHERE elder_id=?').bind(e.id),
      env.DB.prepare('DELETE FROM elders WHERE id=?').bind(e.id),
    ]);
    return { ok: true };
  },

  async subscribe(env, req, b) {
    const role = b.role === 'elder' ? 'elder' : 'family';
    const e = await findBy(env, req, role === 'elder' ? 'elder_code' : 'family_code', b.code);
    checkSubscription(env, b.subscription);
    const s = b.subscription;
    await env.DB.prepare(
      `INSERT INTO subs (endpoint,elder_id,role,p256dh,auth,each_checkin,created_at) VALUES (?,?,?,?,?,?,?)
       ON CONFLICT(endpoint,elder_id,role) DO UPDATE SET p256dh=excluded.p256dh, auth=excluded.auth, each_checkin=excluded.each_checkin`)
      .bind(s.endpoint, e.id, role, s.keys.p256dh, s.keys.auth, b.each ? 1 : 0, Date.now()).run();
    return { ok: true };
  },

  async unsubscribe(env, req, b) {
    const role = b.role === 'elder' ? 'elder' : 'family';
    const e = await findBy(env, req, role === 'elder' ? 'elder_code' : 'family_code', b.code);
    await env.DB.prepare('DELETE FROM subs WHERE endpoint=? AND elder_id=? AND role=?').bind(String(b.endpoint), e.id, role).run();
    return { ok: true };
  },

  async renew(env, req, b) {
    checkSubscription(env, b.subscription);
    const s = b.subscription;
    await env.DB.prepare('UPDATE subs SET endpoint=?,p256dh=?,auth=? WHERE endpoint=?').bind(s.endpoint, s.keys.p256dh, s.keys.auth, String(b.oldEndpoint)).run();
    return { ok: true };
  },

  async testPush(env, req, b) {
    const role = b.role === 'elder' ? 'elder' : 'family';
    const e = await findBy(env, req, role === 'elder' ? 'elder_code' : 'family_code', b.code);
    if (!(await hit(env, 'test:' + e.id, 10, 3600))) throw new Fail(429, '測試太多次了，請一小時後再試。');
    const s = await env.DB.prepare('SELECT * FROM subs WHERE endpoint=? AND elder_id=? AND role=?').bind(String(b.endpoint), e.id, role).first();
    if (!s) throw new Fail(404, '這支手機還沒開啟通知。');
    const ok = await pushOne(env, s, { title: '通知測試成功', body: `之後${e.nickname}的平安提醒會這樣跳出來。`, tag: 'test' });
    return { sent: ok ? 1 : 0 };
  },
};

// ---------- 排程：每 5 分鐘 ----------
// 由資料庫挑出現在該處理的人，所以 Worker 的 CPU 不會隨總人數增加。kind：0 第一次通知家人、1 第二次、2 提醒長輩
const DUE_SQL = `
WITH zone AS (
  SELECT json_extract(value,'$[0]') tz, json_extract(value,'$[1]') day, json_extract(value,'$[2]') hm FROM json_each(?1)
)
SELECT e.*, z.day today, CASE WHEN z.hm < e.deadline THEN 2 WHEN e.alert_day IS z.day THEN 1 ELSE 0 END kind
FROM elders e JOIN zone z ON e.tz = z.tz
WHERE e.last_day IS NOT z.day AND z.day >= e.start_day AND (e.pause_until IS NULL OR z.day > e.pause_until)
  AND ((z.hm >= e.deadline AND (e.alert_day IS NOT z.day OR (e.alert_count = 1 AND e.alert_at <= ?2)))
    OR (z.hm < e.deadline AND z.hm >= e.remind_at AND e.remind_day IS NOT z.day))
ORDER BY kind, e.id LIMIT ?3`;

function sweepMessage(e) {
  if (e.kind === 2) return { title: '今天按「我很好」了嗎？', body: '按一下，讓家人安心。', tag: 'remind' };
  return {
    title: `${e.nickname}今天還沒報平安`,
    body: e.kind === 0 ? `過了 ${e.deadline} 還沒按「我很好」，打個電話問問吧。` : `到現在還是沒有按「我很好」，請聯絡${e.nickname}或附近的親友。`,
    tag: 'late-' + e.id,
  };
}
function sweepWrite(env, e, sent, t) {
  if (e.kind === 2) return env.DB.prepare('UPDATE elders SET remind_day=? WHERE id=?').bind(e.today, e.id);
  return env.DB.prepare('UPDATE elders SET alert_day=?,alert_count=?,alert_at=?,alert_sent=?,remind_day=? WHERE id=?')
    .bind(e.today, e.kind === 0 ? 1 : 2, t, sent, e.today, e.id);
}
async function sendDue(env, t) {
  const { results: zones } = await env.DB.prepare('SELECT DISTINCT tz FROM elders').all();
  const zoneNow = zones.map(({ tz }) => { const n = localNow(tz, t); return [tz, n.day, n.hm]; });
  const { results: due } = await env.DB.prepare(DUE_SQL).bind(JSON.stringify(zoneNow), t - SECOND_ALERT_MS, SWEEP_ELDERS).all();
  if (!due.length) return;
  const { results: subs } = await env.DB.prepare('SELECT * FROM subs WHERE elder_id IN (SELECT value FROM json_each(?))').bind(JSON.stringify(due.map((e) => e.id))).all();
  const phones = (e) => subs.filter((s) => s.elder_id === e.id && s.role === (e.kind === 2 ? 'elder' : 'family')).slice(0, MAX_PHONES);
  let left = SWEEP_PUSHES, i = 0;
  while (i < due.length && left > 0) {
    const chunk = [];
    while (i < due.length && chunk.length < SWEEP_CHUNK) {
      const n = phones(due[i]).length;
      if (chunk.length && n > left) break;
      chunk.push(due[i++]);
      left -= n;
    }
    // 每批寫回一次：就算這一輪被中斷，已送出的人也不會重送
    const writes = await Promise.all(chunk.map(async (e) => {
      const msg = sweepMessage(e);
      const done = await Promise.all(phones(e).map((s) => pushOne(env, s, msg)));
      return sweepWrite(env, e, done.filter(Boolean).length, t);
    }));
    await env.DB.batch(writes);
  }
}
// 這幾句會掃過整張表，每輪都跑的話光 checkins 就吃掉每日讀取額度，所以一天一次
async function cleanup(env, t) {
  const keep = new Date(t - KEEP_DAYS * 864e5).toISOString().slice(0, 10);
  const idle = t - IDLE_DELETE_DAYS * 864e5;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM checkins WHERE day<?').bind(keep),
    env.DB.prepare('DELETE FROM rate WHERE exp<?').bind(t),
    env.DB.prepare('DELETE FROM subs WHERE elder_id IN (SELECT id FROM elders WHERE last_seen<?)').bind(idle),
    env.DB.prepare('DELETE FROM elders WHERE last_seen<?').bind(idle),
  ]);
}
async function sweep(env, scheduledAt) {
  const t = Date.now(), at = new Date(scheduledAt);
  try {
    await sendDue(env, t);
  } finally {
    if (at.getUTCHours() === CLEANUP_UTC_HOUR && at.getUTCMinutes() < 5) await cleanup(env, t);
  }
}

// ---------- 進入點 ----------
function cors(req) {
  const o = req.headers.get('Origin') || '';
  const ok = o === 'https://m255525.github.io' || /^http:\/\/(localhost|127\.0\.0\.1):8860$/.test(o);
  return { 'Access-Control-Allow-Origin': ok ? o : 'https://m255525.github.io', 'Access-Control-Allow-Methods': 'POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', Vary: 'Origin' };
}
export default {
  async fetch(req, env, ctx) {
    const h = cors(req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: h });
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { ...h, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
    const name = new URL(req.url).pathname.replace(/^\/api\//, '');
    if (req.method !== 'POST' || !Object.hasOwn(actions, name)) return json({ error: '找不到這個功能。' }, 404);
    try {
      const body = await req.json().catch(() => ({}));
      return json(await actions[name](env, req, body, ctx));
    } catch (e) {
      if (e instanceof Fail) return json({ error: e.message }, e.status);
      console.log('error', e && e.stack);
      return json({ error: '伺服器暫時出問題，請稍後再試。' }, 500);
    }
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(sweep(env, event.scheduledTime)); },
};
