"""licensekit.core — 卡密 / 令牌 / 存储 的核心实现（无框架依赖）

设计要点
--------
* 卡密：96 bit 随机 + 20 bit HMAC 校验位，Crockford Base32，24 字符分 4 组
* 入库：只存 sha256(卡密)，泄露数据库等于泄露空表；前缀仅作展示"提示"
* 令牌：header.payload.signature，ECDSA P-256 + SHA-256（DER 签名，Android 原生可验）
* 客户端只持公钥：无法伪造令牌；服务端私钥永不下发
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------- 基础编码

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CROCKFORD_MAP = {c: i for i, c in enumerate(CROCKFORD)}
CROCKFORD_MAP.update({c.lower(): i for i, c in enumerate(CROCKFORD)})
# 易混淆字符归一到 Crockford 的规范形
CROCKFORD_MAP.update({"i": 1, "l": 1, "o": 0, "u": 0})


def b32(data: bytes) -> str:
    acc = 0
    bits = 0
    out = []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(CROCKFORD[(acc >> bits) & 0x1F])
    if bits:
        out.append(CROCKFORD[(acc << (5 - bits)) & 0x1F])
    return "".join(out)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_dec(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def now() -> int:
    return int(time.time())


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def ct_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------- 卡密

class CardCodec:
    """卡密编解码。checksum_key 由服务端持有，保证卡不能被外部批量伪造。"""

    BODY_LEN = 20          # 96 bit -> 20 个 base32 字符
    CHECK_LEN = 4          # 20 bit 校验 -> 4 个字符
    GROUP = 6

    def __init__(self, checksum_key: bytes, card_secret: bytes | None = None):
        self.checksum_key = checksum_key
        # card_secret 用于派生"与卡密一一对应的对称密钥"，可用于加密下发配置
        self.card_secret = card_secret or checksum_key

    # -- 生成 --
    def generate(self) -> str:
        body = b32(os.urandom(12))[: self.BODY_LEN]
        return self._format(body + self._checksum(body))

    def _format(self, raw: str) -> str:
        raw = raw.upper()
        return "-".join(raw[i:i + self.GROUP] for i in range(0, len(raw), self.GROUP))

    def _checksum(self, body: str) -> str:
        mac = hmac.new(self.checksum_key, body.encode(), hashlib.sha256).digest()
        return b32(mac)[: self.CHECK_LEN]

    # -- 校验 --
    @staticmethod
    def canonical(code: str) -> str:
        """把任意书写形式（带不带连字符、大小写、易混字符）归一成 24 字符规范形。"""
        out = []
        for c in code.upper():
            if c in CROCKFORD_MAP:
                out.append(CROCKFORD[CROCKFORD_MAP[c]])
        return "".join(out)

    @staticmethod
    def normalize(code: str) -> str:
        cleaned = "".join(c for c in code.upper() if c.isalnum())
        out = []
        for c in cleaned:
            if c not in CROCKFORD_MAP:
                raise ValueError(f"非法字符: {c!r}")
            out.append(CROCKFORD[CROCKFORD_MAP[c]])
        return "".join(out)

    def check(self, code: str) -> str | None:
        """返回规范化后的 24 字符卡密；格式或校验位不对返回 None。"""
        try:
            raw = self.normalize(code)
        except ValueError:
            return None
        if len(raw) != self.BODY_LEN + self.CHECK_LEN:
            return None
        body, check = raw[: self.BODY_LEN], raw[self.BODY_LEN:]
        if not ct_equal(check, self._checksum(body)):
            return None
        return raw

    @staticmethod
    def hash_of(raw: str) -> str:
        return sha256_hex("LICv1:" + CardCodec.canonical(raw))

    @staticmethod
    def hint_of(raw: str) -> str:
        """展示用：前 4 + 后 4，客服核对时用。"""
        canon = CardCodec.canonical(raw)
        return f"{canon[:4]}…{canon[-4:]}"

    def derive_key(self, raw: str, purpose: str) -> bytes:
        """从卡密派生对称密钥（例如加密下发的配置/资源），服务端与客户端都能算。"""
        return hmac.new(self.card_secret,
                        f"{purpose}:{CardCodec.canonical(raw)}".encode(),
                        hashlib.sha256).digest()


# ---------------------------------------------------------------- 密钥

def gen_root_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def gen_signing_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def priv_to_pem(key: ec.EllipticCurvePrivateKey, password: bytes | None = None) -> bytes:
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


def pub_to_pem(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_priv(pem_bytes: bytes, password: bytes | None = None) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem_bytes, password=password)


def load_pub(pem_bytes: bytes) -> ec.EllipticCurvePublicKey:
    return serialization.load_pem_public_key(pem_bytes)


def sign_root(root_key: ec.EllipticCurvePrivateKey, kid: str, signing_pub_pem: bytes) -> str:
    """根密钥对签名公钥做背书（离线执行，签完根私钥可以锁进保险柜）。"""
    msg = b"LICENSE-SIGNING-KEY-v1|" + kid.encode() + b"|" + hashlib.sha256(signing_pub_pem).digest()
    der = root_key.sign(msg, ec.ECDSA(hashes.SHA256()))
    return b64u(der)


def verify_root(root_pub: ec.EllipticCurvePublicKey, kid: str, signing_pub_pem: bytes, sig: str) -> bool:
    msg = b"LICENSE-SIGNING-KEY-v1|" + kid.encode() + b"|" + hashlib.sha256(signing_pub_pem).digest()
    try:
        root_pub.verify(b64u_dec(sig), msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------- 令牌

HEADER = {"alg": "ES256", "typ": "LIC", "v": 1}


class TokenError(Exception):
    pass


@dataclass
class Token:
    raw: str
    claims: dict[str, Any]

    @property
    def expires_at(self) -> int:
        return int(self.claims["exp"])


def issue_token(priv: ec.EllipticCurvePrivateKey, kid: str,
                sub: str, dev: str, plan: str, ttl: int,
                features: Iterable[str] = (), extra: dict | None = None) -> Token:
    header = dict(HEADER)
    header["kid"] = kid
    iat = now()
    claims = {
        "iss": "lic-server",
        "sub": sub,               # 卡密提示（不含明文卡号）
        "dev": dev,               # 设备指纹哈希（前 22 位足够）
        "plan": plan,
        "feat": list(features),
        "iat": iat,
        "nbf": iat - 60,          # 容忍客户端时钟慢 1 分钟
        "exp": iat + ttl,
        "jti": uuid.uuid4().hex,
    }
    if extra:
        claims.update(extra)
    signing_input = b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode()) + "." + \
                    b64u(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    der = priv.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    return Token(signing_input + "." + b64u(der), claims)


def verify_token(token: str, pubkeys: dict[str, ec.EllipticCurvePublicKey],
                 device: str | None = None, skew: int = 120,
                 revoked: Iterable[str] = ()) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("令牌结构错误")
    head_b64, body_b64, sig_b64 = parts
    try:
        header = json.loads(b64u_dec(head_b64))
        claims = json.loads(b64u_dec(body_b64))
        der = b64u_dec(sig_b64)
    except Exception as exc:  # noqa: BLE001
        raise TokenError(f"令牌解码失败: {exc}") from exc

    if header.get("alg") != "ES256":
        raise TokenError("不支持的算法")
    kid = header.get("kid")
    pub = pubkeys.get(kid)
    if pub is None:
        raise TokenError(f"未知签名密钥 kid={kid}")
    try:
        pub.verify(der, f"{head_b64}.{body_b64}".encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise TokenError("签名无效") from exc

    ts = now()
    if claims.get("nbf", 0) - skew > ts:
        raise TokenError("令牌尚未生效")
    if claims.get("exp", 0) + skew < ts:
        raise TokenError("令牌已过期")
    if device is not None and not ct_equal(claims.get("dev", ""), device):
        raise TokenError("设备不匹配")
    if claims.get("jti") in set(revoked):
        raise TokenError("令牌已被吊销")
    return claims


# ---------------------------------------------------------------- 设备指纹

def device_fingerprint(android_id: str, package: str, cert_sha256: str, salt: str) -> str:
    """稳定、不可逆的设备标识。

    Android 8+ 的 ANDROID_ID 按 (签名, 用户) 隔离，重装/换签名会变，
    正好用来做"一台设备一份授权"。salt 由服务端下发或内置，防止被彩虹表反查。
    """
    raw = f"{salt}|{android_id}|{package}|{cert_sha256}".encode()
    return sha256_hex(raw)[:32]


# ---------------------------------------------------------------- 存储

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS cards (
    card_hash     TEXT PRIMARY KEY,
    hint          TEXT NOT NULL,
    plan          TEXT NOT NULL,
    max_devices   INTEGER NOT NULL DEFAULT 1,
    status        TEXT NOT NULL DEFAULT 'active',   -- active | revoked
    created_at    INTEGER NOT NULL,
    first_used_at INTEGER,
    note          TEXT
);
CREATE TABLE IF NOT EXISTS activations (
    card_hash   TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    device_name TEXT,
    created_at  INTEGER NOT NULL,
    last_seen_at INTEGER,
    status      TEXT NOT NULL DEFAULT 'active',     -- active | unbound | revoked
    PRIMARY KEY (card_hash, device_id)
);
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    card_hash TEXT,
    device_id TEXT,
    ip        TEXT,
    detail    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


@dataclass
class Activation:
    card_hash: str
    device_id: str
    device_name: str
    created_at: int
    last_seen_at: int


@dataclass
class Card:
    card_hash: str
    hint: str
    plan: str
    max_devices: int
    status: str
    created_at: int
    first_used_at: int | None = None
    note: str | None = None


class Store:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    # -- 卡 --
    def add_card(self, card: Card) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO cards(card_hash,hint,plan,max_devices,status,created_at,note)"
                " VALUES(?,?,?,?,?,?,?)",
                (card.card_hash, card.hint, card.plan, card.max_devices,
                 card.status, card.created_at, card.note))

    def get_card(self, card_hash: str) -> Card | None:
        row = self.db.execute("SELECT * FROM cards WHERE card_hash=?", (card_hash,)).fetchone()
        return Card(**dict(row)) if row else None

    def revoke_card(self, card_hash: str) -> bool:
        with self.db:
            cur = self.db.execute("UPDATE cards SET status='revoked' WHERE card_hash=?", (card_hash,))
        return cur.rowcount > 0

    def touch_card(self, card_hash: str) -> None:
        with self.db:
            self.db.execute(
                "UPDATE cards SET first_used_at=COALESCE(first_used_at,?) WHERE card_hash=?",
                (now(), card_hash))

    # -- 激活 --
    def activations(self, card_hash: str, active_only: bool = True) -> list[Activation]:
        sql = "SELECT * FROM activations WHERE card_hash=?"
        if active_only:
            sql += " AND status='active'"
        rows = self.db.execute(sql, (card_hash,)).fetchall()
        return [Activation(r["card_hash"], r["device_id"], r["device_name"] or "",
                           r["created_at"], r["last_seen_at"] or 0) for r in rows]

    def add_activation(self, card_hash: str, device_id: str, device_name: str) -> None:
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO activations(card_hash,device_id,device_name,created_at,last_seen_at,status)"
                " VALUES(?,?,?,?,?, 'active')",
                (card_hash, device_id, device_name, now(), now()))

    def unbind(self, card_hash: str, device_id: str) -> bool:
        with self.db:
            cur = self.db.execute(
                "UPDATE activations SET status='unbound'"
                " WHERE card_hash=? AND device_id=? AND status='active'",
                (card_hash, device_id))
        return cur.rowcount > 0

    def seen(self, card_hash: str, device_id: str) -> None:
        with self.db:
            self.db.execute(
                "UPDATE activations SET last_seen_at=? WHERE card_hash=? AND device_id=?",
                (now(), card_hash, device_id))

    # -- 风控 --
    def device_card_count(self, device_id: str, window_days: int = 7) -> int:
        since = now() - window_days * 86400
        row = self.db.execute(
            "SELECT COUNT(DISTINCT card_hash) c FROM activations WHERE device_id=? AND created_at>=?",
            (device_id, since)).fetchone()
        return int(row["c"])

    def log(self, kind: str, card_hash: str | None, device_id: str | None,
            ip: str | None, detail: str = "") -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO events(ts,kind,card_hash,device_id,ip,detail) VALUES(?,?,?,?,?,?)",
                (now(), kind, card_hash, device_id, ip, detail[:500]))

    def stats(self) -> dict[str, int]:
        q = lambda sql: int(self.db.execute(sql).fetchone()[0])  # noqa: E731
        return {
            "cards_total": q("SELECT COUNT(*) FROM cards"),
            "cards_active": q("SELECT COUNT(*) FROM cards WHERE status='active'"),
            "cards_revoked": q("SELECT COUNT(*) FROM cards WHERE status='revoked'"),
            "devices_bound": q("SELECT COUNT(*) FROM activations WHERE status='active'"),
        }