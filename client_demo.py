"""examples/client_demo.py — 参考客户端（同时是端到端自测脚本）

    python -m licensekit.cli init
    python -m licensekit.cli issue -n 1 --plan pro
    python -m licensekit.server --port 8710 &
    python examples/client_demo.py --card XXXX-XXXX-XXXX-XXXX

流程：激活 → 在线校验 → 离线验签 → 篡改检测 → 换机检测 → 解绑
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from licensekit import core  # noqa: E402

STATE = "license_state.json"


def post(url: str, payload: dict, headers: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def get(url: str) -> tuple[int, dict]:
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, json.loads(r.read())


class Client:
    def __init__(self, server: str, data_dir: str, device: dict):
        self.server = server.rstrip("/")
        self.data_dir = data_dir
        self.device = device
        self.pubkeys = self._load_pubkeys()

    def _load_pubkeys(self) -> dict:
        with open(os.path.join(self.data_dir, "pubkeys.json"), encoding="utf-8") as f:
            kd = json.load(f)
        return {kid: core.load_pub(pem.encode()) for kid, pem in kd.items()}

    def activate(self, card: str) -> dict:
        code, body = post(f"{self.server}/v1/activate", {"card": card, "device": self.device})
        if code != 200:
            raise RuntimeError(f"激活失败 {code}: {body}")
        self._save(body["token"])
        return body

    def verify_online(self) -> dict:
        token = self._load_token()
        code, body = post(f"{self.server}/v1/verify",
                          {"token": token, "device": self.device,
                           "nonce": os.urandom(8).hex()})
        if code != 200:
            raise RuntimeError(f"校验失败 {code}: {body}")
        if "token" in body:
            self._save(body["token"])
        return body

    def verify_offline(self, token: str | None = None) -> dict:
        token = token or self._load_token()
        return core.verify_token(token, self.pubkeys)

    def unbind(self) -> dict:
        token = self._load_token()
        code, body = post(f"{self.server}/v1/unbind", {"token": token, "device": self.device})
        if code != 200:
            raise RuntimeError(f"解绑失败 {code}: {body}")
        return body

    def _save(self, token: str) -> None:
        json.dump({"token": token}, open(STATE, "w", encoding="utf-8"))

    def _load_token(self) -> str:
        return json.load(open(STATE, encoding="utf-8"))["token"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://127.0.0.1:8710")
    ap.add_argument("--data", default="data")
    ap.add_argument("--card", required=True)
    args = ap.parse_args()

    device = {
        "android_id": "d2f4a1c9b7e80356",
        "package": "com.demo.app",
        "cert_sha256": "A1B2C3D4" * 8,
        "name": "Xiaomi 14 / HyperOS",
    }
    c = Client(args.server, args.data, device)
    fails = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal fails
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}{('  ' + detail) if detail else ''}")
        if not ok:
            fails += 1

    print("1) 激活")
    r = c.activate(args.card)
    print(f"   token 长度 {len(r['token'])}  到期 {r['expires_at']}  plan={r['plan']}")
    check("拿得到令牌", bool(r["token"]))

    print("2) 在线校验")
    v = c.verify_online()
    check("服务端放行", v.get("ok") is True, f"claims.exp={v['expires_at']}")

    print("3) 离线验签（只靠内置公钥）")
    claims = c.verify_offline()
    check("签名有效", claims["plan"] == "pro", f"plan={claims['plan']} feat={claims['feat']}")
    check("设备绑定一致", claims["dev"] == r["device_id"][:22])

    print("4) 篡改检测")
    token = c._load_token()
    head, body, sig = token.split(".")
    forged = json.loads(core.b64u_dec(body))
    forged["exp"] = forged["exp"] + 31536000
    forged_token = f"{head}.{core.b64u(json.dumps(forged, separators=(',', ':'), sort_keys=True).encode())}.{sig}"
    try:
        c.verify_offline(forged_token)
        check("过期时间被改后应拒绝", False)
    except core.TokenError as exc:
        check("过期时间被改后应拒绝", True, str(exc))

    print("5) 换设备重放")
    other = dict(device)
    other["android_id"] = "0000000000000000"
    try:
        core.verify_token(token, c.pubkeys,
                          device=core.device_fingerprint(other["android_id"], other["package"],
                                                         other["cert_sha256"], salt="k1")[:22])
        check("换机后应拒绝", False)
    except core.TokenError as exc:
        check("换机后应拒绝", True, str(exc))

    print("6) 解绑 → 再校验")
    c.unbind()
    code, body = post(f"{c.server}/v1/verify",
                      {"token": token, "device": device, "nonce": os.urandom(8).hex()})
    check("解绑后服务端拒绝", code == 403, f"{code} {body.get('error')}")

    print()
    print("全部通过" if fails == 0 else f"{fails} 项失败")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())