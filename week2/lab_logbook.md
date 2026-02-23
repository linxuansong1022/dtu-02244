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

### OFMC 完整输出
```
SUMMARY:  ATTACK_FOUND
GOAL:     secrets
TIME:     233 ms
depth:    2 plies
visitedNodes: 20 nodes

ATTACK TRACE:
i -> (P,1): {i, P, x209}_inv(pk(i))
(P,1) -> i: {i, P, ReqP(1)}_inv(pk(P))
i -> (P,1): {x311}_pk(P)
i learns: x311   ← Photos 泄露
```

### 攻击步骤解析

攻击中各变量对应关系：`x32` = 扮演 P 角色的诚实代理，`x311` = Photos，`i` = 入侵者。

| 步骤 | 实际发生 | 对应协议消息 |
|------|---------|------------|
| ① | 入侵者冒充 A，向 P 发送请求，**将 B 的身份设置为 P 自己**（`A=i, B=P`） | $M_1$: `A->P` |
| ② | P 信任该请求，向”B”（实为 P 自己）发出转发请求，被入侵者截获 | $M_2$: `P->B` |
| ③ | 入侵者**跳过 M3、M4 的令牌交换**，直接冒充 B 向 P 发送伪造的 Photos | $M_5$: `B->P` |
| ④ | 入侵者自己选定了 Photos 的值 `x311`，因此入侵者知道它 | 违反 secrecy 目标 |

### 根本原因分析

**漏洞一：P 从未验证 M5 的来源合法性**

P 的行为逻辑是：收到 $M_1$ → 发出 $M_2$ → 等待 $M_5$。但 P 在接收 $M_5$（照片）时，**没有任何机制验证发送方是否真的经过了 M3/M4 的令牌授权流程**。入侵者可以完全绕过 B，直接向 P 发送 $M_5$。

**漏洞二：B 的身份未绑定，导致自引用攻击**

入侵者在 $M_1$ 中将 `B` 设置为 `P` 自身（`B = x32 = P`）。P 不检查 B 是否合理，直接向”自己”转发了请求，入侵者拦截后完成攻击。

**漏洞三：Photos 无绑定保护**

`{Photos}pk(P)` 只加密了内容，但任何人（包括入侵者）都可以用 `pk(P)` 构造一条包含任意值的消息发给 P。Photos 的值由发送方控制，入侵者自选的值自然自己知道。

## 5. 后续改进计划
* 下周计划引入身份提供商（IdP）进行更真实的密钥分发模拟。
* 研究如何防御重放攻击（Replay Attacks），并考虑加密 $Token$ 的传输。
