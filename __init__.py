"""licensekit — 卡密 + 设备绑定 + 签名令牌 的极简授权体系。

客户端只持有公钥，因此反编译无法伪造令牌；
服务端只存卡密哈希，因此拖库不等于泄露卡号。
"""
from __future__ import annotations

from .core import (
    Card,
    CardCodec,
    Store,
    TokenError,
    device_fingerprint,
    gen_root_key,
    gen_signing_key,
    issue_token,
    load_priv,
    load_pub,
    priv_to_pem,
    pub_to_pem,
    sign_root,
    verify_root,
    verify_token,
)

__version__ = "1.0.0"

__all__ = [
    "Card",
    "CardCodec",
    "Store",
    "TokenError",
    "device_fingerprint",
    "gen_root_key",
    "gen_signing_key",
    "issue_token",
    "load_priv",
    "load_pub",
    "priv_to_pem",
    "pub_to_pem",
    "sign_root",
    "verify_root",
    "verify_token",
    "__version__",
]