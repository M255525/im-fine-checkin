// 本機整合測試：先在 worker/ 跑 `npx wrangler dev --port 8799 --test-scheduled`，再 node tools/test_worker.mjs
// 假推播伺服器會實際解密 Worker 送來的內容並驗證 VAPID 簽章，確認加密不是「看起來有送」。
import http from 'node:http';
import crypto from 'node:crypto';

const API = 'http://127.0.0.1:8799';
const b64 = (b) => Buffer.from(b).toString('base64url');
let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m); };
const post = async (a, b) => { const r = await fetch(`${API}/api/${a}`, { method: 'POST', body: JSON.stringify(b) }); return { s: r.status, ...(await r.json()) }; };

function device() {
  const ecdh = crypto.createECDH('prime256v1'); ecdh.generateKeys();
  return { ecdh, auth: crypto.randomBytes(16), inbox: [] };
}
function hkdf(salt, ikm, info, len) { return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len)); }
function decrypt(d, buf) {
  const salt = buf.subarray(0, 16), idlen = buf[20], asPub = buf.subarray(21, 21 + idlen), ct = buf.subarray(21 + idlen);
  const shared = d.ecdh.computeSecret(asPub);
  const ikm = hkdf(d.auth, shared, Buffer.concat([Buffer.from('WebPush: info\0'), d.ecdh.getPublicKey(), asPub]), 32);
  const cek = hkdf(salt, ikm, Buffer.from('Content-Encoding: aes128gcm\0'), 16);
  const nonce = hkdf(salt, ikm, Buffer.from('Content-Encoding: nonce\0'), 12);
  const g = crypto.createDecipheriv('aes-128-gcm', cek, nonce);
  g.setAuthTag(ct.subarray(ct.length - 16));
  const p = Buffer.concat([g.update(ct.subarray(0, ct.length - 16)), g.final()]);
  if (p[p.length - 1] !== 2) throw new Error('padding delimiter');
  return JSON.parse(p.subarray(0, -1).toString());
}
function vapidOk(h) {
  const m = /^vapid t=([^,]+), k=(.+)$/.exec(h || ''); if (!m) return false;
  const [hd, pl, sig] = m[1].split('.');
  const pub = Buffer.from(m[2], 'base64url');
  const key = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64(pub.subarray(1, 33)), y: b64(pub.subarray(33)) }, format: 'jwk' });
  return crypto.verify('sha256', Buffer.from(hd + '.' + pl), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'base64url'));
}

const devices = {}; let badSig = 0, gone = 0;
const srv = http.createServer((q, s) => {
  const ch = []; q.on('data', (c) => ch.push(c)); q.on('end', () => {
    if (q.url === '/gone') { gone++; s.writeHead(410); return s.end(); }
    const d = devices[q.url.slice(1)];
    if (!vapidOk(q.headers.authorization)) badSig++;
    try { d.inbox.push(decrypt(d, Buffer.concat(ch))); } catch (e) { d.inbox.push({ error: String(e) }); }
    s.writeHead(201); s.end();
  });
});
await new Promise((r) => srv.listen(8798, '127.0.0.1', r));
const subOf = (name) => { const d = devices[name] ||= device(); return { endpoint: `http://127.0.0.1:8798/${name}`, keys: { p256dh: b64(d.ecdh.getPublicKey()), auth: b64(d.auth) } }; };
const sweep = async () => { await fetch(`${API}/__scheduled?cron=*/5+*+*+*+*`); await new Promise((r) => setTimeout(r, 1200)); };
const titles = (n) => devices[n].inbox.map((m) => m.title || m.error);

// 時間設成今天早已過，排程一跑就要提醒
const hmNow = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Taipei', hourCycle: 'h23', hour: '2-digit', minute: '2-digit' }).format(new Date());
ok(hmNow > '00:02', '測試需在台北時間 00:03 之後執行，現在 ' + hmNow);
// 建立時若已過時間，當天不該開始算，所以先設很晚再改
const c = await post('create', { nickname: '測試媽', tz: 'Asia/Taipei', remindAt: '23:58', deadline: '23:59' });
ok(c.s === 200 && c.elderCode.length === 12 && c.familyCode !== c.elderCode, '建立長輩');
const bad = await post('create', { nickname: 'x', remindAt: '12:00', deadline: '09:00' });
ok(bad.s === 400, '時間順序錯誤被拒');
ok((await post('family', { code: c.elderCode })).s === 404, '長輩碼不能看家人頁');
ok((await post('elder', { code: c.familyCode })).s === 404, '家人碼不能報平安');
ok((await post('subscribe', { code: c.familyCode, role: 'family', subscription: { endpoint: 'https://evil.example/x', keys: { p256dh: 'a', auth: 'b' } } })).s === 400, '不明推播網址被拒');

await post('subscribe', { code: c.familyCode, role: 'family', subscription: subOf('kid') });
await post('subscribe', { code: c.familyCode, role: 'family', subscription: subOf('kid2'), each: true });
await post('subscribe', { code: c.elderCode, role: 'elder', subscription: subOf('mom') });
await post('subscribe', { code: c.familyCode, role: 'family', subscription: { ...subOf('kid'), endpoint: 'http://127.0.0.1:8798/gone' } });

await sweep();
ok(devices.kid.inbox.length === 0 && devices.mom.inbox.length === 0, '時間未到不通知');

await post('settings', { code: c.familyCode, remindAt: '00:00', deadline: '23:59' });
await sweep();
ok(titles('mom')[0] === '今天按「我很好」了嗎？', '提醒長輩，且內容可解密：' + titles('mom'));
await sweep();
ok(devices.mom.inbox.length === 1, '同一天只提醒一次');

await post('settings', { code: c.familyCode, remindAt: '00:00', deadline: '00:01' });
await sweep();
ok(titles('kid')[0] === '測試媽今天還沒報平安', '過時間通知家人：' + titles('kid'));
ok(gone === 1, '收到 410 的訂閱有被呼叫');
let f = await post('family', { code: c.familyCode });
ok(f.state === 'late' && f.alert.sent === 2 && f.familyDevices === 2, `狀態 late、記錄送達 ${f.alert?.sent}、失效訂閱已刪 (${f.familyDevices})`);
await sweep();
ok(devices.kid.inbox.length === 1, '兩小時內不重複通知');

await post('checkin', { code: c.elderCode });
await new Promise((r) => setTimeout(r, 800));
ok(titles('kid').at(-1) === '測試媽報平安了', '按了之後，已收過警示的家人會收到解除通知');
f = await post('family', { code: c.familyCode });
ok(f.state === 'ok' && f.days.length === 1, '狀態轉為 ok');
await post('checkin', { code: c.elderCode });
f = await post('family', { code: c.familyCode });
ok(f.days.length === 1, '重複按不重複記');

const n = devices.kid.inbox.length;
const call = await post('callMe', { code: c.elderCode });
ok(call.sent === 2 && devices.kid.inbox.length === n + 1, '請家人打電話有送出');

const t = await post('testPush', { code: c.familyCode, role: 'family', endpoint: subOf('kid').endpoint });
ok(t.sent === 1, '測試通知');
ok(!JSON.stringify(devices).includes('"error"') && badSig === 0, `全部通知解密成功、VAPID 簽章正確 (badSig=${badSig})`);

// 暫停中不通知
const c2 = await post('create', { nickname: '測試爸', tz: 'Asia/Taipei', remindAt: '23:58', deadline: '23:59' });
await post('subscribe', { code: c2.familyCode, role: 'family', subscription: subOf('kid3') });
const today = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Taipei' }).format(new Date());
await post('settings', { code: c2.familyCode, remindAt: '00:00', deadline: '00:01', pauseUntil: today });
await sweep();
ok(devices.kid3.inbox.length === 0 && (await post('family', { code: c2.familyCode })).state === 'paused', '暫停中不通知');

// 建立時已過通知時間：今天不警示
const c3 = await post('create', { nickname: '測試姨', tz: 'Asia/Taipei', remindAt: '00:00', deadline: '00:01' });
await post('subscribe', { code: c3.familyCode, role: 'family', subscription: subOf('kid4') });
await sweep();
ok(devices.kid4.inbox.length === 0 && (await post('family', { code: c3.familyCode })).state === 'waiting', '當天太晚建立不會誤報');

// 離線補送：昨天按的算昨天
const yesterdayAt = Date.now() - 30 * 3600e3;
await post('checkin', { code: c3.elderCode, at: yesterdayAt });
f = await post('family', { code: c3.familyCode });
ok(f.days.length === 1 && f.days[0].day < today && f.state !== 'ok', '離線補送算在按下那天');

for (const x of [c, c2, c3]) await post('remove', { code: x.familyCode });
ok((await post('family', { code: c.familyCode })).s === 404, '刪除後查不到');
console.log(`\n${pass} passed, ${fail} failed`);
srv.close(); process.exit(fail ? 1 : 0);
