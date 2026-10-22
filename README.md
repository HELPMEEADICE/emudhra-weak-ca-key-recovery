# eMudhra 中间 CA 弱私钥：事件梳理与 8 把私钥的完整恢复

工作目录 `C:\oss\CVETest\CA`。所有产物在 `fixtures/`（原始数据）、`recovered/`（私钥与报告）、`forgery/`（影响演示）、`tools/`（可复现脚本）。

## 1. 事件

| 时间 (UTC) | 事件 |
| --- | --- |
| 2025-04-30 | eMudhra 在 FIPS 140-2 Level 3 HSM 上做 G3 中间 CA 的密钥生成仪式（KGC）。脚本缺陷使 key wrap/unwrap 之外多产出一套"弱"密钥；因标签相近，被误选去签证书 |
| 2026-10-17 18:05 | 研究者 "Wayne" 向 Apple/Chrome/Microsoft/Mozilla/eMudhra 报告，附 8 把私钥的签名证明 |
| 2026-10-17 19:45 | Chrome CRLSet 按 **SPKI** 拦截 6 张 TLS 中间证书（同时覆盖 Sectigo 交叉签名副本） |
| 2026-10-17 22:59 | Mozilla OneCRL 全量下发；21:48 前 Mozilla 已自行独立恢复私钥 |
| 2026-10-19/20 | Apple、Microsoft 拦截；Android 通过 Play Services 拦截 |
| 2026-10-20 | Mozilla 从 NSS 移除 emSign ECC Root CA - G3；Chrome Root Store v43 跟进 |
| 2026-10-21 | eMudhra 向 BSE 披露：根私钥未受影响，仅 1 张中间 CA 曾上线且未签发过叶证书 |
| 2026-10-22 | eMudhra 吊销全部 8 张中间证书（CRL 见 `crl.emsign.com` / `crl.comodoca.com`） |

受影响对象是 8 个**唯一公钥**：DV/OV/EV TLS 各 B、C 两版，加 2 张代码签名 CA；每张另有 Sectigo AAA Certificate Services 的交叉签名副本，共 16 张证书。

来源：
- [Eight eMudhra CA Keys Compromised (The Hacker News)](https://thehackernews.com/2026/10/eight-emudhra-ca-keys-compromised.html)
- [Mozilla Security Blog](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/)
- [Google Security Blog](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)
- [Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Scott Helme: Eight bits of trust](https://scotthelme.co.uk/eight-bits-of-trust-emudhras-ca-keys-cracked-in-milliseconds/)
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/mozilla-google-apple-block-compromised-emudhra-ca-certificates/)（记录 Flüpke 公布的 `EM OV TLS CA - G3C` 私钥值为 4）
- [eMudhra 事件声明](https://emudhra.com/en/post/certificate-security-incident)
- 社区事件页 `emudhra.we-have-a-problem.com`（`impacted-intermediates.json`、`roots.json`、`proof.zip`、`chains.zip`）

## 2. 为什么可算

ECDSA 公钥是曲线上的标量乘法 `Q = d·G`，`d ∈ [1, n-1]`。P-384 正常应有 384 位熵；这里的 `d` 只有 3–8 位，候选空间小于 256。对每个候选 `d` 计算 `d·G` 与证书 SPKI 比对，命中即私钥——确定性恢复，不是搜索签名。

`recover.py` 用增量点加（每步一次仿射点加），8 个目标并行匹配，**5–7 ms** 内全部命中，与公开报道的 `{4, 56, 66, 115, 155, 156, 230, 237}` 完全一致。

## 3. 恢复结果

| 证书 | 用途 | 签发者 | SPKI SHA-256 | 私钥 d | 有效强度 | 私钥文件 |
| --- | --- | --- | --- | --- | --- | --- |
| EM DV TLS CA - G3B | TLS DV (NL) | emSign Root TLS CA - G3 | EBED6475…B5105 | 156 `0x9c` | 8 bit | `recovered/EM-DV-TLS-CA-G3B-*.key.pem` |
| EM OV TLS CA - G3B | TLS OV (NL) | emSign Root TLS CA - G3 | 43BFFA19…2717B | 155 `0x9b` | 8 bit | `recovered/EM-OV-TLS-CA-G3B-*.key.pem` |
| EM EV TLS CA - G3B | TLS EV (NL) | emSign Root TLS CA - G3 | E0254C7F…5A8A41 | 115 `0x73` | 7 bit | `recovered/EM-EV-TLS-CA-G3B-*.key.pem` |
| EM DV TLS CA - G3C | TLS DV (US) | emSign Root TLS CA - G3 | 49DD353D…34FE5F | 230 `0xe6` | 8 bit | `recovered/EM-DV-TLS-CA-G3C-*.key.pem` |
| **EM OV TLS CA - G3C** | TLS OV (US) | emSign Root TLS CA - G3 | 63ECEFEE…109CF8 | **4** `0x04` | **3 bit** | `recovered/EM-OV-TLS-CA-G3C-*.key.pem` |
| EM EV TLS CA - G3C | TLS EV (US) | emSign Root TLS CA - G3 | 5C0660A2…1F81A0 | 56 `0x38` | 6 bit | `recovered/EM-EV-TLS-CA-G3C-*.key.pem` |
| EM OV CS CA - G3B | 代码签名 (NL) | emSign Root CS CA - G3 | EC4FFA1A…B4F6B6 | 66 `0x42` | 7 bit | `recovered/EM-OV-CS-CA-G3B-*.key.pem` |
| EM OV CS CA - G3C | 代码签名 (US) | emSign Root CS CA - G3 | 92C063D6…5E0E30 | 237 `0xed` | 8 bit | `recovered/EM-OV-CS-CA-G3C-*.key.pem` |

表中 SPKI 省略了中间位，完整值见 `recovered/keys.json`（按 SPKI 分组，含两张证书的序列号与签发者）。

d = 4 的私钥（PKCS#8）：

```
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAShZANiAAQTglHNUqyS
mMHIqtl3Mh3rl+cJvQtMoKylXcitUdz8nRWJoVl+OlEg4e/WMcY+GDXKyuKYaaYu
FjHoooGBq1ZhbcRdkYq8CfOrDmPPeSqk3O1zh743u6VpVJ8cArJw7Wc=
-----END PRIVATE KEY-----
```

（`openssl ec -in … -text` 会把 `priv` 打印成 47 个 `00` 加一个 `04`。其余 7 把同理由 `tools/recover.py` 导出。）

## 4. 复现

```bash
python tools/recover.py     # 拉 fixtures/impacted-intermediates.json -> 穷举 d -> recovered/
python tools/verify.py      # 三重验证
python tools/forge_leaf.py  # 伪造叶证书 + 两条信任路径验证
```

`verify.py` 的证据：

1. `Q = d·G` 与证书公钥坐标完全相等（`pubkey_match=true`）；
2. 用恢复的私钥签 `"We have a problem here - Wayne"`，再用**证书里的公钥**验签 → OK；
3. 外部交叉核对：`fixtures/proof/*.sig`（Wayne 用这 8 把私钥签的原始证明）用证书公钥验签 → OK；`*.pub.pem` 与证书公钥一致 → OK。

第 3 项是关键：它把"我算出来的 d"和"事件中第三方实际持有的私钥"绑在一起，两边独立指向同一公钥。

## 5. 影响演示

`tools/forge_leaf.py` 用 d = 4 的私钥为占位域名 `login.example-bank.test` 签发叶证书（SAN 含 `*.example-bank.test`），并在仍信任这两条层次的信任库里验证：

```
[verify] emSign 层次 (leaf -> EM OV TLS CA - G3C -> emSign Root TLS CA - G3 -> ECC Root G3)
forged-login.example-bank.test.pem: OK
Chain:
depth=0: C=US, O=Example Bank, CN=login.example-bank.test (untrusted)
depth=1: C=US, O=eMudhra Inc, CN=EM OV TLS CA - G3C (untrusted)
depth=2: C=IN, O=eMudhra Technologies Limited, CN=emSign Root TLS CA - G3
depth=3: C=IN, OU=emSign PKI, O=eMudhra Technologies Limited, CN=emSign ECC Root CA - G3

[verify] Sectigo 交叉签名层次 (leaf -> 同一中间 CA 的 AAA 版 -> AAA Certificate Services)
forged-login.example-bank.test.pem: OK
```

链验证本身不查 OneCRL/CRLSet，所以只会拒绝"已撤信任"的客户端才会挡住它。这正是 Chrome 按 SPKI 而非按证书序列号拦截的原因：公钥相同，交叉签名副本一并对付。

## 6. 检测与处置

- 内部 PKI 体检：对所有中间 CA 做 `Q = d·G` 小标量扫描（`d < 2^20` 几秒可完成），并检查 `d` 的比特长度分布；HSM 之外的任何环节都不得接触明文私钥。
- KGC 审计：wrap/unwrap 环节的日志、标签选择逻辑、双套密钥的生成路径应留痕可查；"弱密钥被误选"意味着选择逻辑没有对密钥强度做断言。
- 客户端侧：按 SPKI hash（`recovered/keys.json` 的键）做拦截，比按证书指纹拦截覆盖面更全；把 `emSign ECC Root CA - G3` 与 Sectigo AAA 从信任库移除前先确认业务链。
- 代码签名场景额外注意：`EM OV CS CA - G3B/G3C` 的密钥同样可算，签名时间戳可掩盖签发时间。

## 7. 目录

```
fixtures/   事件原始数据（impacted-intermediates.json, roots.json, proof/, chains/, 站点 HTML）
recovered/  8 把 PKCS#8 私钥 + keys.json + report.md
forgery/    伪造叶证书、伪造签名、链验证产物
tools/      recover.py, verify.py, forge_leaf.py
```
