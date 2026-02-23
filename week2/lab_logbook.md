# Lab Logbook: Week 2 (Dolev and Yao Model)

## 1. 协议开发概览 (AnB Version: OpenAuth_v1)
本周目标是实现一个基础的身份验证和照片共享协议。

### AnB 代码实现 (`week2_v1.AnB` Snapshot):
```AnB
Protocol: OpenAuth_v1
Types:
  Agent A,B,P;
  Number ReqA,ReqP,Token,Photos;
  Function pk;

Knowledge:
  A: A,B,P,pk(A),pk(B),pk(P),inv(pk(A));
  B: A,B,P,pk(A),pk(B),pk(P),inv(pk(B));
  P: A,B,P,pk(A),pk(B),pk(P),inv(pk(P));

Actions:
  A->P: {A,B,ReqA}inv(pk(A))
  P->B: {A,P,ReqP}inv(pk(P))
  B->A: {P,B,Token}inv(pk(B))
  A->B: {P,B,Token}inv(pk(A))
  B->P: {Photos}pk(P)

Goals:
  Photos secret between B,P
```

## 2. 核心想法 (Core Idea)
* **授权令牌模型**：A 首先通过向 P 发起请求（$M_1$），P 转发请求给 B（$M_2$）。B 返回一个授权令牌 $Token$。A 最终通过签名该 $Token$ 并发送给 B（$M_4$），以向 B 证明其本人已授权 P 访问照片。
* **数据建模**：$Photos$ 建模为一个 `Number` 类型的加密负载，通过 B 使用 P 的公钥加密后发送（$M_5$）。

## 3. 建模考量与简化 (Modeling Considerations)
* **公钥体系简化**：假设所有代理（A, B, P）都预先拥有公钥对，且已知彼此的公钥，本周暂时不涉及身份提供商（IdP）或证书分发。
* **签名 vs. 加密**：为了提高效率并方便调试，我们在身份验证阶段主要使用了数字签名 (`inv(pk(X))`) 来验证身份和消息完整性。

## 4. 遇到的问题与分析 (Problems & Analysis)
* **语法报错**：初期运行 OFMC 时，由于在 `Goals` 段落末尾误加了分号（`;`）导致解析错误。经过调试，已移除多余符号，工具目前运行正常。
* **攻击发现 (OFMC Output)**：
  - OFMC 报告了 `ATTACK_FOUND`。
  - **漏洞分析**：攻击路径显示入侵者 $i$ 利用其自身也是“合法参与者”的身份（拥有自己的公私钥对），可以冒充 A 参与协议或拦截 $Token$。这表明目前的协议在消息绑定（Message Binding）上存在缺陷，且 $Token$ 的机密性未得到充分保护。

## 5. 后续改进计划
* 下周计划引入身份提供商（IdP）进行更真实的密钥分发模拟。
* 研究如何防御重放攻击（Replay Attacks），并考虑加密 $Token$ 的传输。
