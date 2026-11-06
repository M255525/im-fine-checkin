# im-fine-checkin — 「我很好」每日報平安

長輩每天按一個按鈕報平安；過了設定時間沒按，家人手機收到通知。2026-11-04 建立。

- 前端：靜態 `index.html`＋`manual.html`＋PWA，GitHub Pages（`pages.yml`，push master 自動部署）：<https://m255525.github.io/im-fine-checkin/>；visitor-badge `m255525.imfinecheckin`。
- 後端：Cloudflare Worker `im-fine-checkin`（`worker/`，**不隨 git push 部署**，改完要 `cd worker && npx wrangler deploy`）＋D1 `im-fine-checkin`＋排程每 5 分鐘。網址 <https://im-fine-checkin.content-workflow.workers.dev>。
- 本機預覽 port **8860**（8852 被 next-bus-helper 占用）；Worker CORS 只放行 Pages 與 8860，換埠要改 `cors()`。

## 登入序號閘門（2026-11-05，使用者要求比照交通出門助手）
- 序號表：試算表「樂齡工具」（`1Yc2nKmGUmZBfWfZFTKcADKh5w4x-56DYygQudzxtdMg`）分頁 **「每日報平安」**，12 個月，選填人數限制。
- **後端共用** `next-bus-helper/gas/` 那支綁定腳本與部署網址，前端每次都帶 `sheet:'每日報平安'`（`release` 也要帶），不用另外授權。改後端要在 next-bus-helper 改，兩個工具都會受影響。
- `#entryGate` 擋住整個工具；`gateOpen` 為 false 時 `route()`／`api()` 不執行，不呼叫 Worker。
- **和交通出門助手不同**：已登入過的手機（有 `ifc.entrySerial`）直接開啟、背景驗證，只有序號確定無效才上鎖，連線失敗或 server_error 都不擋。原因：長輩開啟時連不上驗證就被擋的話按不了，家人會誤收沒按通知，離線補送也失效。第一次登入仍 fail-closed。
- ⚠ 序號過期或被刪除後長輩按不了，但 Worker 排程照跑，家人每天會收到沒按通知，這是已知後果，手冊已寫；到期前 30 天（`WARN_DAYS`）畫面上方 `#licWarn` 提醒長輩和家人換序號，只有連得上驗證時才會更新。Worker 不驗序號，前端閘門懂技術的人可繞過。
- 序號欄預設隱藏，按「👁 顯示」才明碼，按確認自動遮回。登出在 ⚙ 常用設定「登入序號」。

## 設計原則
- 長輩畫面只做一件事：整扇窗就是按鈕。不要加分頁、表單（登入序號是使用者要求的例外，只在第一次出現）。第二個動作只有「請家人打電話給我」。
- 視覺＝台灣老公寓：深藍二丁掛磁磚牆、鐵窗、藍底白字門牌、燈黃。家人畫面的公寓立面一扇窗一天。字體霞鶩文楷 TC＋Noto Sans TC。不要改回撕日曆（兩個姊妹專案已用）。
- 文案不嚇人：沒按「可能只是忘了」。不可宣稱保證送達、不可說成緊急救援或醫療監護。
- 送不到要講實話：`callMe` 回 `sent` 0、`alert.sent` 0 都要顯示，不要假裝成功。

## 架構
- 沒有帳號。每位長輩一列，有兩組 12 碼：`elder_code` 只能報平安／請打電話，`family_code` 看紀錄和改設定。家人裝置可追多位長輩（`ifc.families`）。
- 連結 `?openExternalBrowser=1#e=碼`／`#f=碼`：LINE 內建瀏覽器收不到通知，這個參數讓 LINE 跳到外部瀏覽器。讀到後存 localStorage 並把碼從網址清掉。
- iPhone 的主畫面 App 和 Safari 不共用 localStorage，所以有「我有配對碼」手動輸入這條路，不要拿掉。
- 通知＝Web Push（RFC 8291 aes128gcm＋VAPID），Worker 用 WebCrypto 手寫，不依賴套件。公鑰在 `wrangler.toml`，私鑰是 Worker secret `VAPID_PRIVATE`；本機備份 `worker/vapid.secret.json`（gitignore）。**換金鑰會讓所有現有訂閱失效**。
- 訂閱網址限 FCM／Apple／Mozilla／Windows 的主機（防 SSRF），本機測試靠 `.dev.vars` 的 `ALLOW_LOCAL_PUSH=1`。
- 排程 `sweep()`：`remind_at` 提醒長輩 → `deadline` 通知家人 → 2 小時後再一次。之後按了，所有家人收到解除通知（同 tag 取代警示）。平常只通知選「每次都通知」的人。
- 排程容量：`DUE_SQL` 在資料庫挑出該處理的人，Worker CPU 不隨總人數增加。免費方案每次排程只有 10 毫秒 CPU、50 次對外請求，所以一輪最多 15 則推播、40 位長輩（`SWEEP_PUSHES`／`SWEEP_ELDERS`），做不完下一輪接著送；順序是第一次通知家人→第二次→提醒長輩。每 5 位寫回一次，中斷也不重送。每位長輩每輪最多送 30 支手機（`MAX_PHONES`）。清理會掃整張 `checkins`，只在台北凌晨 3 點跑，**不要改回每輪都跑**（會吃光每日讀取額度）。
- 當天過了 deadline 才建立的，`start_day` 設隔天，不誤報。「今天」以長輩時區（`tz`）計。
- 離線按：寫 `ifc.pending`，恢復後用原本時間補送（36 小時內有效）。畫面要說「還沒送出」。
- 資料保留：`checkins` 100 天；180 天沒人用（`last_seen`）整組刪除。手冊與警語都寫了這些數字，改了要同步。
- 範例模式 `#demo-elder`／`#demo-family`：`demoApi()` 全在前端，不打後端。
- 示範案例 `#demo-case`：模擬時鐘跑一天，`CASES` 7 個案例，長輩＋家人手機並排，全在前端、不打後端、不發真通知，**是唯一不需序號就能開的畫面**（`freeHash()`）。`caseClock()`／`caseActs` 對照 Worker 的 `sweep()`／`dailyState()`，通知文字也手動複製，**改 Worker 規則或文案要一起改**。
- 儲存鍵前綴 `ifc.`。測試掛鉤 `window._ifc`。

## 標準配備
跑馬燈（工作區公告 GAS，滑鼠移入暫停，不可關）、⚙ 常用設定（收合式＋關於本工具）、首訪警語＋頁面入口、`manual.html#creator` 完整版、PWA、訪客計數器。
`manual.html` 由 `tools/build_manual.py` 組出，改手冊要改 `tools/manual_body.html` 再重跑。改 `index.html` 上線時要升 `service-worker.js` 的 `CACHE_NAME`。

## 測試
- 後端：`cd worker && npx wrangler d1 execute im-fine-checkin --local --file=schema.sql`，`npx wrangler dev --port 8799 --ip 127.0.0.1 --test-scheduled`，再 `node tools/test_worker.mjs`（假推播伺服器實際解密並驗 VAPID 簽章，需台北時間 00:03 後跑）。
- 排程負載：同一個 wrangler dev（`--port 8863`）跑 `API=http://127.0.0.1:8863 node tools/test_sweep_load.mjs`，會清空本機 D1。要指定排程時間得打 `/cdn-cgi/handler/scheduled?time=毫秒`，`/__scheduled` 會忽略 `time`。
- 驗證真實通知：Windows 上 `registration.getNotifications()` 查不到原生通知，會誤判成沒收到。要在 SW 暫時記錄 push 事件才準。Playwright 用 `channel='chrome'`。
- 已驗：Worker → FCM → Chrome SW → 解密 → 通知，5 秒內。**未驗：Apple 推播（iPhone 真機）**。
