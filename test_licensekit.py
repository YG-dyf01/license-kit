"""licensekit 测试：单元 + 端到端（不依赖 pytest，`python -m unittest` 即可）"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from licensekit import bootstrap, core  # noqa: E402
from licensekit.core import CardCodec, Store, TokenError  # noqa: E402
from licensekit.server import App, Config, Handler  # noqa: E402

KEY = bytes(range(32))
SECRET = bytes(range(32, 64))
DEVICE = {"android_id": "d2f4a1c9b7e80356", "package": "com.demo.app",
          "cert_sha256": "A1B2C3D4" * 8, "name": "Test Phone"}


class TestCardCodec(unittest.TestCase):
    def setUp(self):
        self.codec = CardCodec(KEY, SECRET)

    def test_format(self):
        card = self.codec.generate()
        self.assertRegex(card, r"^[0-9A-HJKMNP-TV-Z]{6}(-[0-9A-HJKMNP-TV-Z]{6}){3}$")
        self.assertEqual(len(card.replace("-", "")), 24)

    def test_roundtrip_is_stable(self):
        card = self.codec.generate()
        self.assertEqual(self.codec.check(card), card.replace("-", ""))

    def test_canonical_tolerates_user_input(self):
        card = self.codec.generate()
        messy = " " + card.lower().replace("-", " ") + " "
        self.assertEqual(CardCodec.canonical(messy), card.replace("-", ""))
        self.assertEqual(self.codec.check(messy), card.replace("-", ""))

    def test_tampered_checksum_rejected(self):
        card = self.codec.generate()
        flipped = card[:-1] + ("0" if card[-1] != "0" else "1")
        self.assertIsNone(self.codec.check(flipped))

    def test_random_string_rejected(self):
        self.assertIsNone(self.codec.check("000000-000000-000000-000000"))
        self.assertIsNone(self.codec.check("too-short"))

    def test_hash_does_not_leak_card(self):
        card = self.codec.generate()
        h = CardCodec.hash_of(card)
        self.assertNotIn(card[:6].lower(), h)
        self.assertEqual(h, CardCodec.hash_of(card.replace("-", "")))

    def test_derive_key_is_deterministic_and_card_bound(self):
        a, b = self.codec.generate(), self.codec.generate()
        self.assertEqual(self.codec.derive_key(a, "config"), self.codec.derive_key(a, "config"))
        self.assertNotEqual(self.codec.derive_key(a, "config"), self.codec.derive_key(b, "config"))
        self.assertNotEqual(self.codec.derive_key(a, "config"), self.codec.derive_key(a, "asset"))


class TestToken(unittest.TestCase):
    def setUp(self):
        self.priv = core.gen_signing_key()
        self.pub = {"k1": self.priv.public_key()}
        self.dev = core.device_fingerprint("abc", "com.demo.app", "FF", salt="k1")[:22]

    def test_roundtrip(self):
        tok = core.issue_token(self.priv, "k1", "ABCD…WXYZ", self.dev, "pro", 3600, ["core"])
        claims = core.verify_token(tok.raw, self.pub, device=self.dev)
        self.assertEqual(claims["plan"], "pro")
        self.assertEqual(claims["feat"], ["core"])

    def test_expired_rejected(self):
        tok = core.issue_token(self.priv, "k1", "X", self.dev, "pro", -3600)
        with self.assertRaises(TokenError):
            core.verify_token(tok.raw, self.pub, device=self.dev)

    def test_unknown_kid_rejected(self):
        tok = core.issue_token(self.priv, "k9", "X", self.dev, "pro", 3600)
        with self.assertRaises(TokenError):
            core.verify_token(tok.raw, self.pub, device=self.dev)

    def test_tampered_payload_rejected(self):
        tok = core.issue_token(self.priv, "k1", "X", self.dev, "pro", 3600)
        head, body, sig = tok.raw.split(".")
        claims = json.loads(core.b64u_dec(body))
        claims["exp"] += 86400 * 365
        forged = core.b64u(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
        with self.assertRaises(TokenError):
            core.verify_token(f"{head}.{forged}.{sig}", self.pub, device=self.dev)

    def test_device_mismatch_rejected(self):
        tok = core.issue_token(self.priv, "k1", "X", self.dev, "pro", 3600)
        with self.assertRaises(TokenError):
            core.verify_token(tok.raw, self.pub, device="0" * 22)

    def test_revoked_jti_rejected(self):
        tok = core.issue_token(self.priv, "k1", "X", self.dev, "pro", 3600)
        with self.assertRaises(TokenError):
            core.verify_token(tok.raw, self.pub, device=self.dev, revoked=[tok.claims["jti"]])

    def test_root_endorsement(self):
        root = core.gen_root_key()
        spki = core.pub_to_pem(self.priv.public_key()).decode()
        sig = core.sign_root(root, "k1", spki.encode())
        self.assertTrue(core.verify_root(root.public_key(), "k1", spki.encode(), sig))
        other = core.pub_to_pem(core.gen_signing_key().public_key()).decode()
        self.assertFalse(core.verify_root(root.public_key(), "k1", other.encode(), sig))


class TestDeviceFingerprint(unittest.TestCase):
    def test_deterministic(self):
        a = core.device_fingerprint("id", "pkg", "cert", salt="k1")
        b = core.device_fingerprint("id", "pkg", "cert", salt="k1")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 32)

    def test_sensitive_to_each_component(self):
        base = core.device_fingerprint("id", "pkg", "cert", salt="k1")
        self.assertNotEqual(base, core.device_fingerprint("id2", "pkg", "cert", salt="k1"))
        self.assertNotEqual(base, core.device_fingerprint("id", "pkg2", "cert", salt="k1"))
        self.assertNotEqual(base, core.device_fingerprint("id", "pkg", "cert2", salt="k1"))
        self.assertNotEqual(base, core.device_fingerprint("id", "pkg", "cert", salt="k2"))


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.codec = CardCodec(KEY, SECRET)

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def test_card_lifecycle(self):
        card = self.codec.generate()
        h = CardCodec.hash_of(card)
        self.store.add_card(core.Card(h, CardCodec.hint_of(card), "pro", 2, "active", core.now()))
        got = self.store.get_card(h)
        self.assertIsNotNone(got)
        self.assertEqual(got.plan, "pro")
        self.assertTrue(self.store.revoke_card(h))
        self.assertEqual(self.store.get_card(h).status, "revoked")

    def test_activation_counting(self):
        card = self.codec.generate()
        h = CardCodec.hash_of(card)
        self.store.add_card(core.Card(h, "x", "pro", 2, "active", core.now()))
        self.store.add_activation(h, "dev1", "p1")
        self.store.add_activation(h, "dev2", "p2")
        self.assertEqual(len(self.store.activations(h)), 2)
        self.assertTrue(self.store.unbind(h, "dev1"))
        self.assertEqual(len(self.store.activations(h)), 1)


class TestServerEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.data = cls.tmp.name
        info = bootstrap.init_data_dir(cls.data)
        cls.admin = info["admin_token"]
        Handler.app = App(Config(cls.data))
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        Handler.app.store.db.close()   # Windows 下不关连接就删不掉临时目录
        cls.tmp.cleanup()

    def call(self, path, payload=None, headers=None, method="POST"):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def issue(self, plan="pro", max_devices=1):
        code, body = self.call("/admin/issue",
                               {"count": 1, "plan": plan, "max_devices": max_devices},
                               {"X-Admin-Token": self.admin})
        self.assertEqual(code, 200)
        return body["cards"][0]["card"]

    def test_activate_verify_revoke(self):
        card = self.issue()
        code, body = self.call("/v1/activate", {"card": card, "device": DEVICE})
        self.assertEqual(code, 200, body)
        token = body["token"]

        code, body = self.call("/v1/verify", {"token": token, "device": DEVICE, "nonce": "n1"})
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])

        code, _ = self.call("/v1/verify", {"token": token, "device": DEVICE, "nonce": "n1"})
        self.assertEqual(code, 409, "同 nonce 应判重放")

        code, _ = self.call("/admin/revoke", {"card": card}, {"X-Admin-Token": self.admin})
        self.assertEqual(code, 200)

        code, body = self.call("/v1/verify", {"token": token, "device": DEVICE, "nonce": "n2"})
        self.assertEqual(code, 403)
        self.assertEqual(body["error"], "card_revoked")

    def test_device_limit(self):
        card = self.issue(max_devices=1)
        self.assertEqual(self.call("/v1/activate", {"card": card, "device": DEVICE})[0], 200)
        other = dict(DEVICE, android_id="ffffffffffffffff")
        code, body = self.call("/v1/activate", {"card": card, "device": other})
        self.assertEqual(code, 409)
        self.assertEqual(body["error"], "device_limit")

    def test_bad_card_rejected(self):
        code, body = self.call("/v1/activate", {"card": "111111-111111-111111-111111",
                                                "device": DEVICE})
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "card_invalid")

    def test_admin_auth_required(self):
        code, _ = self.call("/admin/issue", {"count": 1}, {"X-Admin-Token": "wrong"})
        self.assertEqual(code, 401)

    def test_unbind_then_verify_fails(self):
        card = self.issue()
        code, body = self.call("/v1/activate", {"card": card, "device": DEVICE})
        token = body["token"]
        self.assertEqual(self.call("/v1/unbind", {"token": token, "device": DEVICE})[0], 200)
        code, body = self.call("/v1/verify", {"token": token, "device": DEVICE, "nonce": "n3"})
        self.assertEqual(code, 403)
        self.assertEqual(body["error"], "device_unbound")


if __name__ == "__main__":
    unittest.main(verbosity=2)