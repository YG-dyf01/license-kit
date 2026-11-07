# 安全说明

## 报告问题

发现令牌伪造、签名绕过、重放、SQL 注入一类问题，请**不要开公开 issue**，
直接发邮件给维护者，或在 GitHub 上用 Security Advisory 私密提交。会在 7 天内回复。

## 部署前必须做的事

1. `data/` 目录（私钥、`config.json`、`license.db`）不进版本库，也不进备份的公开副本。
2. 生产环境把 `server.py` 放在 TLS 终止之后（Nginx/Caddy），不要裸 HTTP 上公网。
3. `admin_token` 通过环境变量或密管系统注入，别写死进镜像。
4. 定期 `python -m licensekit.cli rotate` 轮换签名密钥。
5. 客户端 `allowBackup=false`、`debuggable=false`、`usesCleartextTraffic=false`。

## 已知取舍

- 客户端可被逆向：本项目的目标是「让伪造成本高于购买成本」，不是「不可破解」。
- 离线宽限期由客户端实现，极端情况下可被改时钟绕过；需要强约束时请缩短 TTL 并强制联网。
- 设备指纹基于 `ANDROID_ID`，恢复出厂或换签名会变化，属预期行为。