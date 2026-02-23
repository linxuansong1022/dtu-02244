# Lab Logbook: Week 3 (Lazy Intruder & Identity Provider)

## 1. 协议开发概览 (AnB Version: OpenAuth_v3_IdP)
本周目标是在第二周基础版本上引入身份提供商（IdP），用密码（Password）替代 A 的公私钥对，使协议更贴近真实身份验证场景。

### AnB 代码实现 (`week3_v1.AnB` Snapshot):
```AnB
Protocol: OpenAuth_v3_IdP

Types:
  Agent A,B,P,IdP;
  Number ReqA,Photos,N_A,N_P_req;
  Function pk,pw;

Knowledge:
  A: A,B,P,IdP,pk(B),pk(P),pk(IdP),pw(A);
  B: A,B,P,IdP,pk(B),pk(P),pk(IdP),inv(pk(B));
  P: A,B,P,IdP,pk(B),pk(P),pk(IdP),inv(pk(P));
  IdP: A,B,P,IdP,pk(B),pk(P),pk(IdP),inv(pk(IdP)),pw(A);

Actions:
  A->IdP: A,B,P,ReqA,N_A,pw(A)
  IdP->A: {A,B,P,ReqA,N_A}inv(pk(IdP))
  A->P: {A,B,P,ReqA,N_A}inv(pk(IdP))
  P->B: {{A,B,P,ReqA,N_A}inv(pk(IdP)),N_P_req}inv(pk(P))
  B->P: {Photos}pk(P)

Goals:
  Photos secret between B,P
```

## 2. 与 Week 2 的核心变更 (Changes from Week 2)
* **引入 IdP**：新增第四个参与者 `IdP`，负责签发授权证明。A 不再直接向 P 出示自己的签名，而是先取得 IdP 颁发的令牌，再转发给 P。
* **取消 A 的私钥**：A 的初始知识中不再包含 `inv(pk(A))`，A 自身无法生成签名。
* **引入密码 `pw(A)`**：A 与 IdP 之间以函数 `pw(A)` 表示共享密码。A 通过在首条消息中提交 `pw(A)` 来向 IdP 证明身份。
* **协议从 5 步调整结构**：A→IdP 的认证步骤成为协议第一步，IdP 签发证书后，原 A→P 的授权流程保持不变，P→B 的签名转发方式也随之更新。

## 3. 建模考量 (Modeling Considerations)

### 3.1 密码 `pw(A)` 的处理
* OFMC 的 AnB 语言规定：`Knowledge` 段只允许 `Agent` 类型的变量及其函数应用（如 `pk(A)`、`inv(pk(A))`）出现，不能直接放置 `Number` 类型的值。
* 因此，密码必须声明为 `Function pw`，使用 `pw(A)` 形式（一元函数作用于代理名）来建模"A 专属的密码"，同时将其置于 A 和 IdP 的初始知识中。
* 密码仅作为认证凭证在第一条消息中传输，不用作加密或签名密钥，符合现实中密码使用的限制。

### 3.2 IdP 如何对 A 的请求进行"背书"
* IdP 收到 A 的请求（含 `pw(A)` 作为身份证明）后，使用自己的私钥 `inv(pk(IdP))` 对整个请求内容 `{A,B,P,ReqA,N_A}` 进行签名，生成授权令牌。
* A 将该令牌原封不动地转发给 P，P 使用已知的 `pk(IdP)` 验证签名，从而信任令牌内容。

### 3.3 `Auth_for_P_from_A` 常量的处理
* 初始设计中包含一个常量 `Auth_for_P_from_A`，用于标识令牌用途。
* OFMC 不支持 `Constant` 类型，且 `Number` 类型的值无法直接放入知识段。
* 最终选择将其省略：IdP 签名消息中已包含 A、B、P、ReqA 等字段，令牌的授权语义可由消息内容本身传达，无需额外常量标签。

### 3.4 P 对 B 的签名转发
* P 在向 B 转发时，采用嵌套签名：将 IdP 的令牌与新鲜数 `N_P_req` 一同用 `inv(pk(P))` 签名。
* B 可通过 `pk(P)` 验证来源是 P，并通过内层的 `pk(IdP)` 验证令牌真实性。
* `N_P_req` 的引入是为了防止重放攻击（为 P 本次请求提供新鲜性保证）。

## 4. 遇到的问题与分析 (Problems & Analysis)

### 4.1 AnB 语法错误（调试过程）

| 错误 | 原因 | 修复方式 |
|------|------|---------|
| `-- comment` 注释 | AnB 不支持 `--` 风格的注释 | 删除全部注释 |
| `{msg}_{key}` 下划线语法 | 正确语法为 `{msg}key`，无下划线 | 去除下划线和括号 |
| `<A,B,P>` 尖括号拼接 | AnB 用逗号表示消息拼接，不用 `<>` | 改为直接用逗号 |
| `Constant` 类型声明 | OFMC 不支持 `Constant` 类型 | 改用 `Function` 建模 |
| `Pwd` 作为 `Number` 放入知识段 | 知识段只允许 Agent 函数应用 | 改为 `Function pw`，用 `pw(A)` |
| `Goals` 末尾分号 | 导致解析错误 | 删除分号 |

### 4.2 攻击发现 (OFMC Output: `ATTACK_FOUND`)

#### OFMC 完整输出
```
SUMMARY:      ATTACK_FOUND
GOAL:         secrets
TIME:         228 ms
visitedNodes: 13 nodes
depth:        2 plies

ATTACK TRACE:
i -> (x35,1): {x38,x37,x35,x210,x211}_inv(pk(i))
(x35,1) -> i: {{x38,x37,x35,x210,x211}_inv(pk(i)),NPreq(1)}_inv(pk(x35))
i -> (x35,1): {x313}_(pk(x35))
i -> (i,17): x313
```

#### 变量对应关系（来自 Reached State）

| OFMC 变量 | 对应含义 | 依据 |
|----------|---------|------|
| `x35` | 诚实代理 P | `state_rP(x35,...)` |
| `x37` | 诚实代理 B | `contains(secrecyset(...),x37)` |
| `x38` | 某代理 A | M3 消息中 A 的位置 |
| `x210,x211` | ReqA, N_A | Number 类型新鲜值 |
| `x313` | Photos | `secrets(x313,...,i)` |
| `NPreq(1)` | P 生成的 N_P_req | P 角色实例 1 |
| `pk(i)` | P 眼中"IdP 的公钥" | `state_rP(x35,2,inv(pk(x35)),pk(i),...)` |

> 关键发现：P 的状态中 `pk(i)` 出现在"IdP 公钥"的位置，说明在本次攻击实例化中 **P 的 IdP 变量被绑定为入侵者 `i`**。

#### 攻击步骤解析

```
步骤①  i -> P: {x38,x37,x35,x210,x211}_inv(pk(i))
```
入侵者用**自己的私钥** `inv(pk(i))` 伪造一个"IdP 签名证书"发给 P。
对应协议 M3：`A->P: {A,B,P,ReqA,N_A}inv(pk(IdP))`。
由于 P 的 IdP 变量已绑定为 `i`，P 用 `pk(i)` 验证签名——验证通过。
**A、B、IdP 此时全部处于步骤 0，完全未参与。**

```
步骤②  P -> i: {{x38,x37,x35,x210,x211}_inv(pk(i)),NPreq(1)}_inv(pk(x35))
```
P 接受伪造证书，生成新鲜数 `NPreq(1)`，将请求嵌套签名后发给"B"。
对应协议 M4：`P->B: {{...}inv(pk(IdP)),N_P_req}inv(pk(P))`。
入侵者在网络上截获这条消息（Dolev-Yao 模型中入侵者控制所有网络流量）。

```
步骤③  i -> P: {x313}_pk(x35)
```
入侵者冒充 B，用 P 的公钥加密一个**自己选定的值** `x313` 发给 P。
对应协议 M5：`B->P: {Photos}pk(P)`。
P 用 `inv(pk(P))` 解密，接收了"Photos = x313"。

```
步骤④  i 知道 x313
```
因为 x313 是入侵者自己选的，入侵者当然知道其值。
**违反目标：`Photos secret between B,P`**（B 从未参与，P 收到的是假照片）。

#### 根本原因分析

**原因一（主要）：IdP 身份未固定绑定**

P 的初始知识为 `P: A,B,P,IdP,pk(B),pk(P),pk(IdP),inv(pk(P))`。
其中 `IdP` 是一个可变的 Agent 变量。在 OFMC 的 Dolev-Yao 模型中，入侵者 $i$ 本身也是合法代理，拥有 `pk(i)/inv(pk(i))`。当 P 角色实例化时，`IdP` 变量可以被绑定为任意代理——包括 $i$。一旦 `IdP = i`，入侵者就能签出 P 认为合法的"IdP 证书"。

**原因二（次要）：B 的响应未与 P 的请求绑定**

B 发送 `{Photos}pk(P)` 时，消息中不包含 P 发出的 `N_P_req`。P 无法验证收到的 Photos 是否真的来自对 M4 的响应，任何人都可以用 `pk(P)` 构造一条消息发给 P。

**攻击的本质**：整个攻击仅在入侵者和 P 之间完成，完全绕过了诚实的 A、B 和 IdP。协议依赖的"信任链"（A→IdP→P→B）在没有固定 IdP 身份的情况下，可以被入侵者单独短路。

## 5. 特殊任务：Lazy Intruder 静态分析 (Special Task)

**目标**：证明角色 P 是可执行的（Executable），即入侵者 $i$ 扮演 P 时，能否根据已收到的消息构造出所有需要发出的消息。

**角色配置**：P = $i$（入侵者），A、B、IdP 均为诚实代理。

**入侵者 $i$ 的初始知识**（作为 P 角色）：
$$K_0 = \{ i, A, B, IdP, pk(B), pk(i), pk(IdP), inv(pk(i)) \}$$

---

**Step 1：P 收到 A 的消息**

$$A \to i: \underbrace{\{A, B, i, ReqA, N_A\}_{inv(pk(IdP))}}_{\text{IdP 签名的令牌}}$$

- 收到后，$i$ 将整个密文加入知识库（无需解密，因为没有 $inv(pk(IdP))$）：
$$K_1 = K_0 \cup \{ \{A, B, i, ReqA, N_A\}_{inv(pk(IdP))} \}$$

---

**Step 2：P 向 B 发送转发请求**

P 需要发送：$\{\{A,B,i,ReqA,N_A\}_{inv(pk(IdP))},\ N_{P\_req}\}_{inv(pk(i))}$

推导过程：

| 步骤 | 方法 | 说明 |
|------|------|------|
| 取 $\{A,B,i,ReqA,N_A\}_{inv(pk(IdP))}$ | **Analysis**：直接取自 $K_1$ | 整块密文作为子消息 |
| 生成 $N_{P\_req}$ | **Composition**：新鲜数，$i$ 可自由生成 | 新鲜 Number |
| 用 $inv(pk(i))$ 签名 | **Composition**：$inv(pk(i)) \in K_0$ | $i$ 持有自己的私钥 |

结论：$i$ 可以构造该消息。✓

$$i \to B: \{\{A,B,i,ReqA,N_A\}_{inv(pk(IdP))},\ N_{P\_req}\}_{inv(pk(i))}$$

$$K_2 = K_1 \cup \{ N_{P\_req} \}$$

---

**Step 3：P 收到 B 的消息**

$$B \to i: \{Photos\}_{pk(i)}$$

- $i$ 使用 $inv(pk(i)) \in K_0$ 解密：
  - **Analysis**：$\{Photos\}_{pk(i)}$ 以 $inv(pk(i))$ 解密，得到 $Photos$

$$K_3 = K_2 \cup \{ \{Photos\}_{pk(i)},\ Photos \}$$

---

**结论**：角色 P 的所有发送动作均可由入侵者 $i$ 通过其知识库构造，**P 角色是可执行的（Executable）**。

## 6. 后续改进计划
* 需要解决 IdP 身份绑定问题：P 在接受令牌前，需有机制确认令牌确实来自合法的 IdP（而非任何持有公私钥的代理）。
* 研究如何将 B 的响应与 P 的请求 `N_P_req` 进行绑定，防止入侵者冒充 B 替换 Photos 内容。
* 考虑在下周引入双向认证或 nonce challenge 机制来修复上述漏洞。
