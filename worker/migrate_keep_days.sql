-- 已經建好的資料庫只跑一次，要在部署新版 Worker 之前跑。新建的資料庫用 schema.sql 就好。
ALTER TABLE elders ADD COLUMN keep_days INTEGER NOT NULL DEFAULT 100;
ALTER TABLE elders ADD COLUMN cleared_day TEXT;
