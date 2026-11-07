"""licensekit.server — 授权服务端（标准库，无第三方 Web 框架）

启动：
    python -m licensekit.server --data data --host 127.0.0.1 --port 8710

接口：
    POST /v1/activate   激活卡密 → 返回签名令牌
    POST /v1/verify     校验令牌（含静默续期）
    POST /v1/unbind     解绑当前设备
    GET  /v1/keys       下发公钥集合（支持轮换）
    POST /admin/issue   批量发卡（需 X-Admin-Token）
    POST /admin/revoke  吊销卡密
    GET  /admin/stats   统计
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import core
from .core import CardCodec, Store, TokenError

TOKEN_TTL = 7 * 86400          # 令牌有效期 7 天
REFRESH_WINDOW = 3 * 86400     # 剩余不足 3 天时自动换新
UNBIND_COOLDOWN = 86400        # 同一张卡 24h 内只能解绑一次
MAX_CARDS_PER_DEVICE = 3       # 同一设备 7 天内最多激活 3 张卡（风控）
RATE_LIMIT = (60, 60)          # 每 IP 每 60 秒最多 60 次请求


class Config:
    def __init__(self, data_dir: str):
        self.dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        path = os.path.join(data_dir, "config.json")
        if not os.path.exists(path):
            raise SystemExit(f"缺少配置文件：{path}（先运行 python -m licensekit.cli init）")
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self.admin_token: str = raw["admin_token"]
        self.kid: str = raw["kid"]
        self.checksum_key = bytes.fromhex(raw["checksum_key"])
        self.card_secret = bytes.fromhex(raw["card_secret"])
        self.signing_key_path = os.path.join(data_dir, raw["signing_key"])
        self.keys_path = os.path.join(data_dir, raw.get("keys_file", "pubkeys.json"))

    def load_pubkeys(self) -> dict:
        with open(self.keys_path, "r", encoding="utf-8") as f:
            kd = json.load(f)
        return {kid: core.load_pub(pem.encode()) for kid, pem in kd.items()}


class RateLimiter:
    def __init__(self, limit: int, window: int):
        self.limit, self.window = limit, window
        self.hits: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        t = time.time()
        with self.lock:
            bucket = [x for x in self.hits.get(key, []) if t - x < self.window]
            if len(bucket) >= self.limit:
                self.hits[key] = bucket
                return False
            bucket.append(t)
            self.hits[key] = bucket
            return True


class NonceCache:
    """防重放：同一 (device, nonce) 在窗口内只接受一次。"""

    def __init__(self, ttl: int = 300):
        self.ttl = ttl
        self.seen: dict[str, float] = {}
        self.lock = threading.Lock()

    def offer(self, key: str) -> bool:
        t = time.time()
        with self.lock:
            if len(self.seen) > 20000:
                self.seen = {k: v for k, v in self.seen.items() if t - v < self.ttl}
            if key in self.seen and t - self.seen[key] < self.ttl:
                return False
            self.seen[key] = t
            return True


class App:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.store = Store(os.path.join(cfg.dir, "license.db"))
        self.codec = CardCodec(cfg.checksum_key, cfg.card_secret)
        with open(cfg.signing_key_path, "rb") as f:
            self.signing_key = core.load_priv(f.read())
        self.pubkeys = cfg.load_pubkeys()
        self.limiter = RateLimiter(*RATE_LIMIT)
        self.nonces = NonceCache()

    # ---------------- 业务 ----------------

    def activate(self, body: dict, ip: str) -> tuple[int, dict]:
        raw_card = str(body.get("card", ""))
        dev = body.get("device") or {}
        raw = self.codec.check(raw_card)
        if raw is None:
            self.store.log("activate.bad_format", None, None, ip)
            return 400, {"error": "card_invalid", "message": "卡密格式或校验位不正确"}

        card_hash = CardCodec.hash_of(raw)
        card = self.store.get_card(card_hash)
        if card is None:
            self.store.log("activate.unknown", card_hash, None, ip)
            return 404, {"error": "card_not_found", "message": "卡密不存在"}
        if card.status != "active":
            self.store.log("activate.revoked", card_hash, None, ip)
            return 403, {"error": "card_revoked", "message": "卡密已被吊销"}

        try:
            device_id = core.device_fingerprint(
                str(dev["android_id"]), str(dev["package"]), str(dev["cert_sha256"]),
                salt=self.cfg.kid)
        except KeyError:
            return 400, {"error": "device_invalid", "message": "缺少设备信息"}

        active = self.store.activations(card_hash)
        if not any(a.device_id == device_id for a in active):
            if len(active) >= card.max_devices:
                self.store.log("activate.limit", card_hash, device_id, ip,
                               f"active={len(active)} max={card.max_devices}")
                return 409, {"error": "device_limit", "message": "已达到最大绑定设备数"}
            if self.store.device_card_count(device_id) >= MAX_CARDS_PER_DEVICE:
                self.store.log("activate.abuse", card_hash, device_id, ip, "too_many_cards_on_device")
                return 429, {"error": "risk_control", "message": "该设备近期激活过于频繁"}

        self.store.touch_card(card_hash)
        self.store.add_activation(card_hash, device_id, str(dev.get("name", ""))[:64])
        self.store.log("activate.ok", card_hash, device_id, ip)

        tok = core.issue_token(self.signing_key, self.cfg.kid,
                               sub=card.hint, dev=device_id[:22],
                               plan=card.plan, ttl=TOKEN_TTL,
                               features=_features(card.plan))
        return 200, {
            "token": tok.raw,
            "expires_at": tok.expires_at,
            "plan": card.plan,
            "device_id": device_id,
        }

    def verify(self, body: dict, ip: str) -> tuple[int, dict]:
        token = str(body.get("token", ""))
        dev = body.get("device") or {}
        try:
            device_id = core.device_fingerprint(
                str(dev["android_id"]), str(dev["package"]), str(dev["cert_sha256"]),
                salt=self.cfg.kid)
        except KeyError:
            return 400, {"error": "device_invalid", "message": "缺少设备信息"}

        nonce = str(body.get("nonce", ""))
        if nonce and not self.nonces.offer(f"{device_id}:{nonce}"):
            return 409, {"error": "replay", "message": "重复请求"}

        try:
            claims = core.verify_token(token, self.pubkeys, device=device_id[:22])
        except TokenError as exc:
            self.store.log("verify.fail", None, device_id, ip, str(exc))
            return 401, {"error": "token_invalid", "message": str(exc)}

        card_hash = self._hash_from_hint(claims.get("sub", ""))
        card = self.store.get_card(card_hash) if card_hash else None
        if card is None or card.status != "active":
            self.store.log("verify.revoked", card_hash, device_id, ip)
            return 403, {"error": "card_revoked", "message": "授权已失效"}

        act = [a for a in self.store.activations(card_hash) if a.device_id == device_id]
        if not act:
            self.store.log("verify.unbound", card_hash, device_id, ip)
            return 403, {"error": "device_unbound", "message": "该设备已被解绑"}

        self.store.seen(card_hash, device_id)
        self.store.log("verify.ok", card_hash, device_id, ip)

        resp = {"ok": True, "expires_at": claims["exp"], "plan": card.plan}
        if claims["exp"] - core.now() < REFRESH_WINDOW:
            fresh = core.issue_token(self.signing_key, self.cfg.kid, sub=card.hint,
                                     dev=device_id[:22], plan=card.plan, ttl=TOKEN_TTL,
                                     features=_features(card.plan))
            resp["token"] = fresh.raw
            resp["expires_at"] = fresh.expires_at
        return 200, resp

    def unbind(self, body: dict, ip: str) -> tuple[int, dict]:
        token = str(body.get("token", ""))
        dev = body.get("device") or {}
        try:
            device_id = core.device_fingerprint(
                str(dev["android_id"]), str(dev["package"]), str(dev["cert_sha256"]),
                salt=self.cfg.kid)
            claims = core.verify_token(token, self.pubkeys, device=device_id[:22])
        except (KeyError, TokenError) as exc:
            return 401, {"error": "token_invalid", "message": str(exc)}

        card_hash = self._hash_from_hint(claims.get("sub", ""))
        if not card_hash:
            return 404, {"error": "card_not_found"}
        last = self.store.db.execute(
            "SELECT ts FROM events WHERE kind='unbind.ok' AND card_hash=? ORDER BY ts DESC LIMIT 1",
            (card_hash,)).fetchone()
        if last and core.now() - last["ts"] < UNBIND_COOLDOWN:
            return 429, {"error": "cooldown", "message": "解绑冷却中，请稍后再试"}
        ok = self.store.unbind(card_hash, device_id)
        self.store.log("unbind.ok" if ok else "unbind.noop", card_hash, device_id, ip)
        return (200, {"ok": True}) if ok else (404, {"error": "not_bound"})

    # ---------------- 辅助 ----------------

    def _hash_from_hint(self, hint: str) -> str | None:
        row = self.store.db.execute("SELECT card_hash FROM cards WHERE hint=?", (hint,)).fetchone()
        return row["card_hash"] if row else None


def _features(plan: str) -> list[str]:
    return {
        "basic": ["core"],
        "pro": ["core", "export", "priority"],
        "team": ["core", "export", "priority", "seats5"],
    }.get(plan, ["core"])


class Handler(BaseHTTPRequestHandler):
    app: App
    server_version = "LicenseServer/1.0"

    # -- 工具 --
    def _json(self, code: int, payload: dict) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 64 * 1024:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return {}

    def _ip(self) -> str:
        return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()

    def log_message(self, fmt, *args):  # 静音默认日志
        pass

    # -- 路由 --
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/v1/keys":
            return self._json(200, {"keys": self.app.cfg.load_pubkeys_pem()})
        if path == "/admin/stats":
            if not self._admin_ok():
                return self._json(401, {"error": "unauthorized"})
            return self._json(200, self.app.store.stats())
        if path == "/health":
            return self._json(200, {"ok": True, "ts": core.now()})
        return self._json(404, {"error": "not_found"})

    def do_POST(self):
        if not self.app.limiter.allow(self._ip()):
            return self._json(429, {"error": "rate_limited"})
        path = urlparse(self.path).path
        body = self._body()
        ip = self._ip()

        if path == "/v1/activate":
            code, payload = self.app.activate(body, ip)
        elif path == "/v1/verify":
            code, payload = self.app.verify(body, ip)
        elif path == "/v1/unbind":
            code, payload = self.app.unbind(body, ip)
        elif path == "/admin/issue":
            code, payload = self._admin_issue(body)
        elif path == "/admin/revoke":
            code, payload = self._admin_revoke(body)
        else:
            code, payload = 404, {"error": "not_found"}
        return self._json(code, payload)

    # -- 管理 --
    def _admin_ok(self) -> bool:
        token = self.headers.get("X-Admin-Token", "")
        return core.ct_equal(token, self.app.cfg.admin_token)

    def _admin_issue(self, body: dict) -> tuple[int, dict]:
        if not self._admin_ok():
            return 401, {"error": "unauthorized"}
        count = max(1, min(int(body.get("count", 1)), 500))
        plan = str(body.get("plan", "basic"))
        max_devices = max(1, min(int(body.get("max_devices", 1)), 5))
        note = str(body.get("note", ""))[:200]
        out = []
        for _ in range(count):
            raw = self.app.codec.generate()
            h = CardCodec.hash_of(raw)
            self.app.store.add_card(core.Card(h, CardCodec.hint_of(raw), plan,
                                              max_devices, "active", core.now(), note))
            out.append({"card": raw, "hint": CardCodec.hint_of(raw)})
        self.app.store.log("admin.issue", None, None, self._ip(), f"count={count} plan={plan}")
        return 200, {"cards": out}

    def _admin_revoke(self, body: dict) -> tuple[int, dict]:
        if not self._admin_ok():
            return 401, {"error": "unauthorized"}
        raw = self.app.codec.check(str(body.get("card", "")))
        if raw is None:
            return 400, {"error": "card_invalid"}
        ok = self.app.store.revoke_card(CardCodec.hash_of(raw))
        self.app.store.log("admin.revoke", CardCodec.hash_of(raw), None, self._ip())
        return (200, {"ok": True}) if ok else (404, {"error": "card_not_found"})


def _load_pubkeys_pem(self) -> list[dict]:
    with open(self.keys_path, "r", encoding="utf-8") as f:
        kd = json.load(f)
    return [{"kid": kid, "spki": pem} for kid, pem in kd.items()]


Config.load_pubkeys_pem = _load_pubkeys_pem


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8710)
    args = ap.parse_args()

    cfg = Config(args.data)
    app = App(cfg)
    Handler.app = app
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[lic] listening on http://{args.host}:{args.port}  kid={cfg.kid}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[lic] bye")


if __name__ == "__main__":
    main()