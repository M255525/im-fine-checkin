// 排程負載測試：灌大量長輩進本機 D1，確認每輪限量、家人通知優先、不重送、跨時區、每日清理。
// 用法：在 worker/ 跑 `npx wrangler dev --port 8863 --ip 127.0.0.1 --test-scheduled`，再 API=http://127.0.0.1:8863 node tools/test_sweep_load.mjs
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';

const API = process.env.API || 'http://127.0.0.1:8863';
const PORT = 8864, BUDGET = 15, IDLE = 2000, ALERTS = 20, REMINDS = 20;
let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m); };
const workerDir = path.join(import.meta.dirname, '..', 'worker');
const sql = (file) => execSync(`npx wrangler d1 execute im-fine-checkin --local --file="${file}"`, { cwd: workerDir, stdio: 'pipe' });

const got = [];
const srv = http.createServer((q, s) => { q.resume(); q.on('end', () => { got.push(q.url.slice(1)); s.writeHead(201); s.end(); }); });
await new Promise((r) => srv.listen(PORT, '127.0.0.1', r));
const sweep = async (time) => {
  const before = got.length;
  await fetch(`${API}/cdn-cgi/handler/scheduled?cron=*/5+*+*+*+*${time ? `&time=${time}` : ""}`);
  await new Promise((r) => setTimeout(r, 1500));
  return got.slice(before);
};

const ecdh = crypto.createECDH('prime256v1'); ecdh.generateKeys();
const p256 = ecdh.getPublicKey().toString('base64url'), auth = crypto.randomBytes(16).toString('base64url');
const today = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Taipei' }).format(new Date());
const lines = ['DELETE FROM elders;', 'DELETE FROM subs;', 'DELETE FROM checkins;', 'DELETE FROM rate;'];
const old = Date.now() - 200 * 864e5, fresh = Date.now();
const elder = (id, tz, remind, deadline, lastDay, lastSeen = fresh) => lines.push(`INSERT INTO elders (id,elder_code,family_code,nickname,tz,remind_at,deadline,start_day,created_at,last_seen,last_day) VALUES (${id},'E${id}','F${id}','t${id}','${tz}','${remind}','${deadline}','2000-01-01',${fresh},${lastSeen},${lastDay ? `'${lastDay}'` : 'NULL'});`);
const sub = (id, role, name) => lines.push(`INSERT INTO subs (endpoint,elder_id,role,p256dh,auth,created_at) VALUES ('http://127.0.0.1:${PORT}/${name}',${id},'${role}','${p256}','${auth}',${fresh});`);
let id = 1;
for (let i = 0; i < IDLE; i++, id++) elder(id, 'Asia/Taipei', '23:58', '23:59', today);
for (let i = 0; i < ALERTS; i++, id++) { elder(id, i < 5 ? 'America/New_York' : 'Asia/Taipei', '00:00', i < 5 ? '00:00' : '00:01'); sub(id, 'family', 'alert' + i); sub(id, 'elder', 'wrong' + i); }
for (let i = 0; i < REMINDS; i++, id++) { elder(id, 'Asia/Taipei', '00:00', '23:59'); sub(id, 'elder', 'remind' + i); sub(id, 'family', 'wrong' + (100 + i)); }
const stale = id; elder(stale, 'Asia/Taipei', '23:58', '23:59', today, old);
lines.push(`INSERT INTO checkins (elder_id,day,at) VALUES (1,'2000-01-01',0);`);
const seed = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ifc-')), 'seed.sql');
fs.writeFileSync(seed, lines.join('\n'));
sql(seed);

const r1 = await sweep();
ok(r1.length === BUDGET && r1.every((x) => x.startsWith('alert')), `第 1 輪只送 ${BUDGET} 則且全是通知家人：${r1.length}`);
const r2 = await sweep();
ok(r2.length === BUDGET && r2.filter((x) => x.startsWith('alert')).length === ALERTS - BUDGET, `第 2 輪先補完家人通知再提醒長輩：${r2.length}`);
const r3 = await sweep();
ok(r3.length === ALERTS + REMINDS - 2 * BUDGET, `第 3 輪送完剩下的：${r3.length}`);
const r4 = await sweep();
ok(r4.length === 0, '全部送完後不再送');
ok(new Set(got).size === got.length, '沒有人被重送');
ok(!got.some((x) => x.startsWith('wrong')), '通知對象沒有送錯角色');
ok(got.filter((x) => x.startsWith('alert')).length === ALERTS, '兩個時區的家人都收到');

const left = () => JSON.parse(execSync(`npx wrangler d1 execute im-fine-checkin --local --json --command "SELECT (SELECT COUNT(*) FROM elders WHERE id=${stale}) e,(SELECT COUNT(*) FROM checkins) c"`, { cwd: workerDir, stdio: 'pipe' }).toString())[0].results[0];
const noon = new Date(); noon.setUTCHours(12, 0, 0, 0);
await sweep(noon.getTime());
ok(left().e === 1 && left().c === 1, '非清理時段不刪資料');
const night = new Date(); night.setUTCHours(19, 0, 0, 0);
await sweep(night.getTime());
ok(left().e === 0 && left().c === 0, '清理時段刪掉過期紀錄與閒置帳號');

fs.writeFileSync(seed, 'DELETE FROM elders; DELETE FROM subs; DELETE FROM checkins; DELETE FROM rate;');
sql(seed);
console.log(`\n${pass} passed, ${fail} failed`);
srv.close(); process.exit(fail ? 1 : 0);
