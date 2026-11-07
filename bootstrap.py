"""licensekit.bootstrap — 数据目录初始化（CLI 与测试共用）

生成：
    <data>/config.json          管理令牌、卡密校验密钥、当前 kid
    <data>/root_key.pem         根私钥（离线保存）
    <data>/signing_k1.pem       签名私钥（只放服务器）
    <data>/pubkeys.json         公钥集合（内置进客户端）
    <data>/endorsement.json     根密钥对签名公钥的背书
    <data>/license.db           SQLite
"""
from __future__ import annotations

import json
import os
import secrets

from . import core
from .core import Store

DEFAULT_KID = "k1"


def paths(data_dir: str) -> dict[str, str]:
    return {
        "dir": data_dir,
        "config": os.path.join(data_dir, "config.json"),
        "db": os.path.join(data_dir, "license.db"),
        "keys": os.path.join(data_dir, "pubkeys.json"),
        "root": os.path.join(data_dir, "root_key.pem"),
        "endorsement": os.path.join(data_dir, "endorsement.json"),
    }


def load_config(data_dir: str) -> dict:
    with open(paths(data_dir)["config"], "r", encoding="utf-8") as f:
        return json.load(f)


def init_data_dir(data_dir: str, force: bool = False) -> dict:
    p = paths(data_dir)
    os.makedirs(p["dir"], exist_ok=True)
    if os.path.exists(p["config"]) and not force:
        raise FileExistsError("config.json 已存在；如需重建请加 --force")

    root = core.gen_root_key()
    signing = core.gen_signing_key()
    kid = DEFAULT_KID

    with open(os.path.join(p["dir"], f"signing_{kid}.pem"), "wb") as f:
        f.write(core.priv_to_pem(signing))
    with open(p["root"], "wb") as f:
        f.write(core.priv_to_pem(root))

    spki = core.pub_to_pem(signing.public_key()).decode()
    with open(p["keys"], "w", encoding="utf-8") as f:
        json.dump({kid: spki}, f, indent=2)
    with open(p["endorsement"], "w", encoding="utf-8") as f:
        json.dump({"kid": kid, "endorsement": core.sign_root(root, kid, spki.encode())}, f, indent=2)

    cfg = {
        "kid": kid,
        "admin_token": secrets.token_urlsafe(32),
        "checksum_key": secrets.token_hex(32),
        "card_secret": secrets.token_hex(32),
        "signing_key": f"signing_{kid}.pem",
        "keys_file": "pubkeys.json",
    }
    with open(p["config"], "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    Store(p["db"])
    return {**p, "kid": kid, "admin_token": cfg["admin_token"]}