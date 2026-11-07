# Changelog

## 1.0.0

首个版本。

- 卡密：96 bit 随机 + 20 bit HMAC 校验位，Crockford Base32，24 字符四组
- 令牌：ECDSA P-256 / SHA-256（DER），紧凑三段式，7 天有效期 + 剩余 3 天自动续期
- 设备绑定：`sha256(salt | ANDROID_ID | package | 证书哈希)`
- 服务端：标准库 HTTP + SQLite，activate / verify / unbind / keys + 管理端三个接口
- 运维 CLI：init / issue / list / revoke / rotate / stats
- Android 验签器：`LicenseVerifier.kt`（验签 + 设备指纹 + 请求签名）
- 测试：23 个用例，含真起服务的端到端流程