#!/usr/bin/env python3
"""
验证 recover.py 恢复出的私钥确实是对应证书的私钥。

三层证据：
  1. 重算 Q = d*G，与证书 SPKI 逐字节比对（已在 recover.py 中做）；
  2. 用恢复的私钥对任意消息签名，再用证书公钥验签必须通过；
  3. 与外部证据交叉核对：proof.zip 中 Wayne 用 8 把私钥签名的 sig 值，
     以及 .pub.pem 是否等于证书公钥。
"""
import json
import pathlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

ROOT = pathlib.Path(__file__).resolve().parent.parent
REC = ROOT / "recovered"
PROOF = ROOT / "fixtures" / "proof"
MESSAGE = b"We have a problem here - Wayne"


def load_cert_map():
    entries = json.loads((ROOT / "fixtures" / "impacted-intermediates.json").read_text(encoding="utf-8"))
    m = {}
    for e in entries:
        if e["issuer_operator"] == "eMudhra":
            m[e["name"]] = x509.load_pem_x509_certificate(e["pem"].encode())
    return m


def main():
    keys = json.loads((REC / "keys.json").read_text(encoding="utf-8"))
    certs = load_cert_map()
    ok = True
    print(f"{'cert':<22} {'d':>4}  sign/verify  wayne-sig  pub.pem")
    print("-" * 62)
    for spki, k in keys.items():
        name = k["name"]
        cert = certs[name]
        cert_pub = cert.public_key()
        sk = serialization.load_pem_private_key(
            (ROOT / k["key_file"]).read_bytes(), password=None
        )

        # 2) 自签自验：私钥签名 -> 证书公钥验签
        sig = sk.sign(MESSAGE, ec.ECDSA(hashes.SHA384()))
        try:
            cert_pub.verify(sig, MESSAGE, ec.ECDSA(hashes.SHA384()))
            sv = "OK"
        except InvalidSignature:
            sv = "FAIL"
            ok = False

        # 3a) Wayne 的签名（ECDSA DER 或 r||s 都要兼容）
        # "EM OV TLS CA - G3C" -> "EM-OV-TLS-CA-G3C"（"-" 两侧空格合并不产生连续连字符）
        slug = name.replace(" - ", "-").replace(" ", "-")
        sigf = PROOF / f"{slug}.sig"
        wayne = "-"
        if sigf.exists():
            raw = sigf.read_bytes()
            for cand in (raw, der_to_raw(raw)):
                try:
                    cert_pub.verify(cand, MESSAGE, ec.ECDSA(hashes.SHA384()))
                    wayne = "OK"
                    break
                except (InvalidSignature, ValueError):
                    continue
            if wayne != "OK":
                wayne = "FAIL"
                ok = False

        # 3b) proof 里的 .pub.pem 应等于证书公钥
        pubf = PROOF / f"{slug}.pub.pem"
        pm = "-"
        if pubf.exists():
            p = serialization.load_pem_public_key(pubf.read_bytes())
            pm = "OK" if p.public_numbers() == cert_pub.public_numbers() else "MISMATCH"
            if pm != "OK":
                ok = False

        print(f"{name:<22} {k['d']:>4}  {sv:<11}  {wayne:<9}  {pm}")

    print("-" * 62)
    print("全部通过" if ok else "存在失败项")
    return 0 if ok else 1


def der_to_raw(der: bytes) -> bytes:
    """把 DER 编码的 ECDSA 签名转成 IEEE P1363 r||s（P-384 -> 96 字节）。"""
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(48, "big") + s.to_bytes(48, "big")


if __name__ == "__main__":
    raise SystemExit(main())
