# eMudhra 中间 CA 弱私钥恢复报告

曲线 secp384r1 (P-384)，穷举区间 d ∈ [1, 65536]，判定条件 Q = d·G 与证书 SPKI 完全一致。
穷举耗时 4.3 ms。

| 证书 | 签发者 | 私钥 d (十进制) | d (hex) | 有效强度 | 公钥匹配 |
| --- | --- | --- | --- | --- | --- |
| EM DV TLS CA - G3B | emSign Root TLS CA - G3 (eMudhra) | 156 | 0x9c | 8 bit | ✔ |
| EM OV TLS CA - G3B | emSign Root TLS CA - G3 (eMudhra) | 155 | 0x9b | 8 bit | ✔ |
| EM EV TLS CA - G3B | emSign Root TLS CA - G3 (eMudhra) | 115 | 0x73 | 7 bit | ✔ |
| EM DV TLS CA - G3C | emSign Root TLS CA - G3 (eMudhra) | 230 | 0xe6 | 8 bit | ✔ |
| EM OV TLS CA - G3C | emSign Root TLS CA - G3 (eMudhra) | 4 | 0x04 | 3 bit | ✔ |
| EM EV TLS CA - G3C | emSign Root TLS CA - G3 (eMudhra) | 56 | 0x38 | 6 bit | ✔ |
| EM OV CS CA - G3B | emSign Root CS CA - G3 (eMudhra) | 66 | 0x42 | 7 bit | ✔ |
| EM OV CS CA - G3C | emSign Root CS CA - G3 (eMudhra) | 237 | 0xed | 8 bit | ✔ |
