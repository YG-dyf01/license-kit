"""licensekit.cli — 运维命令行

    python -m licensekit.cli init                   初始化密钥、配置、数据库
    python -m licensekit.cli issue -n 20 --plan pro 离线批量发卡
    python -m licensekit.cli list                   查看卡与绑定
    python -m licensekit.cli revoke <卡号>          吊销
    python -m licensekit.cli rotate                 轮换签名密钥
    python -m licensekit.cli stats                  统计
"""
from __future__ import annotations

import argparse
import json
import os

from . import bootstrap, core
from .core import CardCodec, Store

DATA = "data"


def cmd_init(args) -> None:
    try:
        info = bootstrap.init_data_dir(args.data, force=args.force)
    except FileExistsError as exc:
        raise SystemExit(str(exc)) from exc
    print("初始化完成")
    print(f"  根私钥   : {info['root']}        ← 离线保存，签完可封存")
    print(f"  签名私钥 : {info['dir']}/signing_{info['kid']}.pem  ← 只放服务器")
    print(f"  公钥集合 : {info['keys']}")
    print(f"  管理令牌 : {info['admin_token']}")
    print()
    print("把 pubkeys.json 的内容内置进客户端（只有公钥，泄露无风险）。")


def cmd_issue(args) -> None:
    p = bootstrap.paths(args.data)
    cfg = bootstrap.load_config(args.data)
    codec = CardCodec(bytes.fromhex(cfg["checksum_key"]), bytes.fromhex(cfg["card_secret"]))
    store = Store(p["db"])
    out = []
    for _ in range(args.number):
        raw = codec.generate()
        store.add_card(core.Card(CardCodec.hash_of(raw), CardCodec.hint_of(raw), args.plan,
                                 args.devices, "active", core.now(), args.note))
        out.append(raw)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        print(f"已生成 {len(out)} 张卡 -> {args.out}")
    else:
        for card in out:
            print(card)


def cmd_list(args) -> None:
    p = bootstrap.paths(args.data)
    store = Store(p["db"])
    rows = store.db.execute(
        "SELECT hint, plan, status, max_devices, created_at,"
        " (SELECT COUNT(*) FROM activations a WHERE a.card_hash=c.card_hash AND a.status='active') bound"
        " FROM cards c ORDER BY created_at DESC LIMIT ?", (args.limit,)).fetchall()
    print(f"{'hint':<12}{'plan':<8}{'status':<9}{'max':<5}{'bound':<6}")
    for r in rows:
        print(f"{r['hint']:<12}{r['plan']:<8}{r['status']:<9}{r['max_devices']:<5}{r['bound']:<6}")


def cmd_revoke(args) -> None:
    cfg = bootstrap.load_config(args.data)
    codec = CardCodec(bytes.fromhex(cfg["checksum_key"]), bytes.fromhex(cfg["card_secret"]))
    raw = codec.check(args.card)
    if raw is None:
        raise SystemExit("卡密格式错误")
    store = Store(bootstrap.paths(args.data)["db"])
    print("已吊销" if store.revoke_card(CardCodec.hash_of(raw)) else "未找到该卡")


def cmd_rotate(args) -> None:
    p = bootstrap.paths(args.data)
    cfg = bootstrap.load_config(args.data)
    with open(p["keys"], encoding="utf-8") as f:
        keys = json.load(f)
    new_kid = f"k{len(keys) + 1}"
    signing = core.gen_signing_key()
    with open(os.path.join(p["dir"], f"signing_{new_kid}.pem"), "wb") as f:
        f.write(core.priv_to_pem(signing))
    spki = core.pub_to_pem(signing.public_key()).decode()
    keys[new_kid] = spki
    with open(p["keys"], "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)

    with open(p["root"], "rb") as f:
        root = core.load_priv(f.read())
    endorsement = core.sign_root(root, new_kid, spki.encode())
    with open(os.path.join(p["dir"], f"endorsement_{new_kid}.json"), "w", encoding="utf-8") as f:
        json.dump({"kid": new_kid, "endorsement": endorsement}, f, indent=2)

    cfg["kid"] = new_kid
    cfg["signing_key"] = f"signing_{new_kid}.pem"
    with open(p["config"], "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(f"已轮换到 {new_kid}；旧令牌仍可用旧公钥验签到过期为止。")


def cmd_stats(args) -> None:
    print(json.dumps(Store(bootstrap.paths(args.data)["db"]).stats(), ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    # --data 既接受 `lic --data X init`，也接受 `lic init --data X`
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data", default=argparse.SUPPRESS, metavar="DIR",
                        help=f"数据目录（默认 {DATA}）")

    ap = argparse.ArgumentParser(prog="lic", description="licensekit 运维命令行")
    ap.add_argument("--data", default=argparse.SUPPRESS, metavar="DIR")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", parents=[common], help="初始化密钥与数据库")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("issue", parents=[common], help="批量发卡")
    s.add_argument("-n", "--number", type=int, default=1)
    s.add_argument("--plan", default="basic", choices=["basic", "pro", "team"])
    s.add_argument("--devices", type=int, default=1)
    s.add_argument("--note", default="")
    s.add_argument("--out", default="")
    s.set_defaults(func=cmd_issue)

    s = sub.add_parser("list", parents=[common], help="列出卡密")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("revoke", parents=[common], help="吊销卡密")
    s.add_argument("card")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("rotate", parents=[common], help="轮换签名密钥")
    s.set_defaults(func=cmd_rotate)

    s = sub.add_parser("stats", parents=[common], help="统计")
    s.set_defaults(func=cmd_stats)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not hasattr(args, "data"):
        args.data = DATA
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())