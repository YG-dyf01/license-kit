# license-kit

**卡密 + 设备绑定 + 签名令牌** —— 一套能直接跑起来的最小授权体系。

Python 服务端 · 运维 CLI · 参考客户端 · Android 验签器。除 `cryptography` 外零依赖，
不开数据库服务，不引 Web 框架，`git clone` 后三条命令就能激活一张卡。

```
卡密   JJN6WV-FXKDNA-KMES9X-FGREV9
                                     └ 4 位 HMAC 校验，防止瞎猜
令牌   eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiTElDIiwidiI6MX0.eyJkZXYiOi…
       └ ECDSA P-256 签名，客户端只拿公钥，改一个字就验不过
```

---

## 特性

- **客户端只持公钥**——反编译最多拿到一把公开的钥匙，签不出令牌。
- **数据库只存哈希**——拖库等于拖到一张空表。
- **设备绑定**——`ANDROID_ID + 包名 + 签名证书哈希`，一台设备一份授权。
- **短令牌 + 静默续期**——7 天有效期，剩余 3 天自动换新，封卡最迟一周生效。
- **无损轮换**——换签名密钥后旧令牌照常验签到过期。
- **零框架**——标准库 HTTP 服务 + SQLite，`python -m licensekit.server` 即可。

---

## 快速开始

```bash
pip install cryptography

# 1. 生成根密钥 / 签名密钥 / 配置 / 数据库
python -m licensekit.cli init

# 2. 发两张 pro 卡
python -m licensekit.cli issue -n 2 --plan pro --out cards.txt

# 3. 起服务（另开一个终端）
python -m licensekit.server --port 8710

# 4. 跑一遍完整客户端流程：激活 → 校验 → 离线验签 → 篡改检测 → 解绑
python examples/client_demo.py --card XXXX-XXXX-XXXX-XXXX   # 卡号从 cards.txt 里取
```

也可以用 `pip install -e .` 安装后直接用 `lic` / `lic-server` 两个命令，效果一样。

`init` 会把**管理令牌**打印出来，后面调管理接口要用；`data/` 目录里是私钥，
已经在 `.gitignore` 里，**永远不要提交**。

---

## 架构

```
根密钥 Root (P-256, 离线)
   └─ 背书 → 签名公钥（内置客户端）
签名密钥 Signing k1/k2 (服务器)
   └─ 签发 → license token (ECDSA, 7 天)
卡密 (96bit 随机 + 20bit 校验, 库里只存 sha256)
   └─ 绑定 → 设备指纹
```

```
客户端                          服务端
  │ POST /v1/activate  {card,device}     │ 查卡 → 查重 → 风控 → 绑定 → 签令牌
  │ ◀──────────── {token, expires_at}    │
  │ POST /v1/verify    {token,device,nonce}  验签 + 查卡状态 + 查绑定
  │ ◀────── {ok, expires_at, token?}      │ 剩余 <3 天自动换新
  │ POST /v1/unbind    {token,device}     │ 24h 冷却
```

### HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/activate` | 激活卡密，返回签名令牌 |
| POST | `/v1/verify` | 校验令牌，必要时续期 |
| POST | `/v1/unbind` | 解绑当前设备 |
| GET | `/v1/keys` | 下发公钥集合（轮换用） |
| GET | `/health` | 存活探针 |
| POST | `/admin/issue` | 批量发卡（`X-Admin-Token`） |
| POST | `/admin/revoke` | 吊销卡密 |
| GET | `/admin/stats` | 统计 |

---

## 卡密格式

```
JJN6WV-FXKDNA-KMES9X-FGREV9
└──── 20 字符 = 96 bit 随机 ────┘└ 校验 ┘
```

- Crockford Base32：去掉 `I L O U`，`i/l→1`、`o→0` 自动归一，手抄不易错。
- 校验位 = `HMAC-SHA256(checksum_key, body)` 的前 20 bit——**只有服务端能造出合法卡号**。
- 入库只存 `sha256("LICv1:" + 规范化卡号)`；另存 `hint`（前 4 + 后 4）供客服核对。
- `codec.derive_key(card, "config")` 可用同一张卡派生对称密钥，用来加密下发的配置。

## 令牌

```
header.payload.signature     # 紧凑三段式，签名是 DER 编码的 ECDSA
```

```json
{"iss":"lic-server","sub":"JJN6…REV9","dev":"9f2c1a…","plan":"pro",
 "feat":["core","export","priority"],"iat":1794038400,"nbf":1794038340,
 "exp":1794643200,"jti":"8f3a…"}
```

校验顺序：`alg` → `kid` → 签名 → `nbf/exp`（±120 s）→ `dev` → `jti` 黑名单。
签名是 DER 编码，所以 Android 端 `Signature.getInstance("SHA256withECDSA")` 直接能验。

---

## 安全模型

| 能防 | 不能防 |
|---|---|
| 手输/臆造卡密（HMAC 校验位） | 逆向你整个 App 的人 |
| 一卡多机（设备指纹 + 上限） | 真机 + 真卡的二次分发（靠风控） |
| 改令牌内容（ECDSA 签名） | 内存补丁把 `verify()` 返回值改成 true |
| 换机重放（`dev` 绑定 + `nonce`） | 服务端被打穿（另一个话题） |
| 拖库（只存哈希） | 私钥文件泄露 |

关键原则：**关键功能要依赖服务端下发的数据或令牌**，本地校验只是第一道门。
客户端里永远不要放对称密钥——那是很多卡密系统翻车的根本原因。

---

## 接进 Android

```kotlin
// 1. 内置公钥（可放多把，支持轮换）
val pub = LicenseVerifier.parsePublicKey(BuildConfig.LIC_PUBKEY_K1)

// 2. 设备指纹（与服务端同算法）
val dev = DeviceId.compute(context, salt = "k1")

// 3. 冷启动先离线验签，再异步续期
val claims = LicenseVerifier.verify(tokenFromPrefs, mapOf("k1" to pub), dev)
if ("export" !in claims.features) disableExport()

// 4. 令牌放 EncryptedSharedPreferences，别进日志、别进备份
```

完整实现见 [`examples/android/LicenseVerifier.kt`](examples/android/LicenseVerifier.kt)。

---

## 运维

```bash
python -m licensekit.cli list                        # 看卡与绑定数
python -m licensekit.cli revoke JJN6WV-FXKDNA-…      # 吊销
python -m licensekit.cli rotate                      # 轮换签名密钥（零停机）
python -m licensekit.cli stats                       # 统计
```

内置风控：同设备 7 天最多激活 3 张卡 · 同卡最多 `max_devices` 台 ·
解绑 24h 冷却 · 每 IP 60 次/分钟 · `nonce` 5 分钟去重。

---

## 项目结构

```
license-kit/
├─ licensekit/
│  ├─ core.py        卡密 / 令牌 / 设备指纹 / SQLite
│  ├─ bootstrap.py   数据目录初始化（CLI 与测试共用）
│  ├─ server.py      HTTP 服务
│  └─ cli.py         运维命令行
├─ examples/
│  ├─ client_demo.py 参考客户端 + 端到端自测
│  └─ android/LicenseVerifier.kt
├─ tests/test_licensekit.py   23 个单元 + 端到端用例
├─ pyproject.toml
└─ requirements.txt
```

## 测试

```bash
python -m unittest discover -s tests -v
```

```
Ran 23 tests in 0.6s
OK
```

覆盖：卡密格式与校验位、大小写/连字符归一、篡改拒绝、令牌签发/过期/换机/未知 kid、
根背书、设备指纹的确定性与敏感性、存储层、以及**真的起一个 HTTP 服务**跑完
激活 → 校验 → 重放拦截 → 吊销 → 解绑。

---

## License

MIT，见 [LICENSE](LICENSE)。

---

作者 [YG-dyf01](https://github.com/YG-dyf01) · 仓库 [github.com/YG-dyf01/license-kit](https://github.com/YG-dyf01/license-kit)