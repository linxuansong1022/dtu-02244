# Special Task: Static Analysis (Week 2)

## 1. 任务背景
假设协议在诚实代理（A, B, P）之间运行，入侵者 $i$ 仅作为网络观察者，窃听所有传输的消息，但不主动发送或拦截消息。

## 2. 公开传输的消息 (Network Messages)
根据 `week2_v1.AnB` 的定义，网络上流转的消息如下：
1. $M_1 (A 	o P): \{A, B, ReqA\}_{inv(pk(A))}$ —— A 签名的请求
2. $M_2 (P 	o B): \{A, P, ReqP\}_{inv(pk(P))}$ —— P 转发并签名的请求
3. $M_3 (B 	o A): \{P, B, Token\}_{inv(pk(B))}$ —— B 签发的 Token
4. $M_4 (A 	o B): \{P, B, Token\}_{inv(pk(A))}$ —— A 转发并签名的 Token
5. $M_5 (B 	o P): \{Photos\}_{pk(P)}$ —— B 发送给 P 的加密照片

## 3. 入侵者推导过程 (Dolev-Yao Deduction)
入侵者的初始知识 $M = \{A, B, P, i, pk(A), pk(B), pk(P), pk(i), inv(pk(i))\}$。

### 分析规则 (Analysis Steps):
* **解析签名消息 ($M_1, M_2, M_3, M_4$)**：
  根据 Dolev-Yao 的 `OpenSig` 规则，如果入侵者知道公钥，就能从签名消息中提取内容。
  - 从 $M_1$ 提取：$A, B, ReqA$
  - 从 $M_2$ 提取：$A, P, ReqP$
  - 从 $M_3, M_4$ 提取：$P, B, Token$
* **解密加密消息 ($M_5$)**：
  根据 `DecAsym` 规则，解密 $\{Photos\}_{pk(P)}$ 需要私钥 $inv(pk(P))$。
  - 由于 $inv(pk(P)) 
otin M$，入侵者**无法解密** $M_5$。

## 4. 结论
* **入侵者发现的信息**：入侵者通过窃听获取了协议的所有元数据，包括请求标识符（$ReqA, ReqP$）和授权令牌（$Token$）。
* **机密性评估**：$Photos$ 依然是安全的。在纯被动窃听下，入侵者无法获得被非对称加密保护的敏感数据。
* **潜在风险**：虽然被动攻击无法拿到照片，但由于 $Token$ 是明文传输（仅签名），入侵者在未来如果转为“主动攻击”，可能会利用窃听到的 $Token$ 进行重放攻击。
