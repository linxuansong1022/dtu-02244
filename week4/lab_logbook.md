# Lab Logbook: Week 4 (Secure Implementation and Typing)

## 1. 协议开发概览 (AnB Version: OpenAuth_v4_IdP)
本周目标是在第三周基础版本上引入格式，从而消除类型的混淆，同时去除 A 预知所有公钥的假设，使协议更贴近真实身份验证场景，最终证明协议是 Type-Flaw Resistant。

### AnB 代码实现 (`week4_v1.AnB` Snapshot):
```AnB
Protocol: OpenAuth_v4_IdP

Types:
  Agent A,B,P,IdP;
  Number ReqA,Photos,N_A,N_P_req;
  Function pk,pw;
  Format f1, f2, f3, f4;  
Knowledge:
  A: A,B,P,IdP,pk(IdP),pw(A);
  B: A,B,P,IdP,pk(B),pk(P),pk(IdP),inv(pk(B));
  P: A,B,P,IdP,pk(B),pk(P),pk(IdP),inv(pk(P));
  IdP: A,B,P,IdP,pk(B),pk(P),pk(IdP),inv(pk(IdP)),pw(A);

Actions:
  A->IdP: f1(A, B, P, ReqA, N_A, pw(A))
  IdP->A: {f2(A, B, P, ReqA, N_A)}inv(pk(IdP))
  A->P: {f2(A, B, P, ReqA, N_A)}inv(pk(IdP))
  P->B: {f3({f2(A, B, P, ReqA, N_A)}inv(pk(IdP)), N_P_req)}inv(pk(P))
  B->P: {f4(Photos)}pk(P)

Goals:
  Photos secret between B,P
```

### AnB 代码实现 (`week4_keylookup.AnB` Snapshot):
```AnB
Protocol: KeyLookup  
Types:
  Agent A, X, IdP;  
  Number N_A;
  Function pk;
  Format f1, f2;  
Knowledge:
  A: A,X, IdP, pk(IdP); 
  IdP: IdP, A, X, pk(IdP), inv(pk(IdP)), pk(X);

Actions:
  A->IdP: f1(A, X,N_A)
  IdP->A: {f2(A,X, pk(X),N_A)}inv(pk(IdP))

Goals:
    A authenticates IdP on pk(X),N_A
```

### AnB 代码实现 (`week4_v2.AnB` Snapshot):
```AnB
Protocol: OpenAuth_v5

Types:
  Agent A,B,P,idp;
  Number ReqA,Photos,N_A,N_P_req;
  Function pk,pw;
  Format f1, f2, f3, f4;

Knowledge:
  A: A,B,P,idp,pk(idp),pw(A);
  B: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(B));
  P: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(P));
  idp: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(idp)),pw(A)
where B!=P

Actions:
  A->idp: {f1(B, P, ReqA, N_A, pw(A))}pk(idp)
  idp->A: {f2(B, P, ReqA, N_A)}inv(pk(idp))
  A->P: {f2(B, P, ReqA, N_A)}inv(pk(idp))
  P->B: {f3(B, P, {f2(B, P, ReqA, N_A)}inv(pk(idp)), N_P_req)}inv(pk(P))
  B->P: {{f4(B, P, N_P_req, Photos)}inv(pk(B))}pk(P)

Goals:
  Photos secret between B,P
```
## 2. 与 Week 2 的核心变更 (Changes from Week 2)
* **引入格式**：参照课件中的 Format（格式标签） 方法，为每条消息加上唯一的类型标签，将所有"裸拼接"替换为带格式的结构。
* **去除 A 预知所有公钥的假设**：A 的初始知识中不再包含所有公钥，同时设计一个独立的子协议，让 A 在需要时向 IdP 查询某个参与者的公钥。
* **最终验证协议是 Type-Flaw Resistant**：依据SMP的定义，验证主协议与子协议是 Type-Flaw Resistant 的。

## 3. 遇到的问题与分析 (Problems & Analysis)


### 3.1 代码运行发现 (OFMC Output)

#### OFMC 完整输出
```
ofmc: pk(X) is never known by X
CallStack (from HasCallStack)
```

#### 分析

> 在子协议之中未在A的知识之中添加查询对象

#### OFMC 完整输出
```
SUMMARY: ATTACK_FOUND GOAL: weak_auth
```

#### 分析

> 发现了弱认证，经过检查发现是未在回复信息之中添加接收方信息A，之后添加接收方同时在信息之中添加A每次发送的随机数N_A，一次确保解决重放问题

#### 子协议 OFMC 完整输出
```
SUMMARY:
  NO_ATTACK_FOUND
GOAL:
  as specified
DETAILS:
  BOUNDED_NUMBER_OF_SESSIONS
BACKEND:
  Open-Source Fixedpoint Model-Checker version 2024
STATISTICS:
  TIME 15 ms
  parseTime 0 ms
  visitedNodes: 73 nodes
  depth: 7 plies
```

#### 主协议 OFMC 完整输出
```
SUMMARY:
  ATTACK_FOUND
GOAL:
  secrets
BACKEND:
  Open-Source Fixedpoint Model-Checker version 2024
STATISTICS:
  TIME 62 ms
  parseTime 0 ms
  visitedNodes: 11 nodes
  depth: 2 plies

ATTACK TRACE:
i -> (x39,1): {f2,x42,x41,x39,x210,x211}_inv(pk(i))
(x39,1) -> i: {f3,{f2,x42,x41,x39,x210,x211}_inv(pk(i)),NPreq(1)}_inv(pk(x39))
i -> (x39,1): {f4,x313}_(pk(x39))
i can produce secret x313

secret leaked: x313
```


#### 变量对应关系（来自 Reached State）

| OFMC 变量 | 对应含义 | 依据 |
|----------|---------|------|
| `x39` | 诚实代理 P | `state_rP(x39,...)` |
| `x41` | 诚实代理 B | `contains(secrecyset(...),x41)` |
| `x42` | 某代理 A | M3 消息中 A 的位置 |
| `x210,x211` | ReqA, N_A | Number 类型新鲜值 |
| `x313` | Photos | `secrets(x313,...,i)` |
| `NPreq(1)` | P 生成的 N_P_req | P 角色实例 1 |
| `pk(i)` | P 眼中"IdP 的公钥" | `state_rP(x39,2,inv(pk(x39)),pk(i),...)` |

> 关键发现：P 的状态中 `pk(i)` 出现在"IdP 公钥"的位置，说明在本次攻击实例化中 **P 的 IdP 变量被绑定为入侵者 `i`**。

#### 攻击步骤解析

```
步骤①  i -> P: {f2,x42,x41,x39,x210,x211}_inv(pk(i))
```
入侵者用**自己的私钥** `inv(pk(i))` 伪造一个"IdP 签名证书"发给 P。
对应协议 M3：`A->P: A->P: {f2(A, B, P, ReqA, N_A)}inv(pk(IdP))`。
由于 P 的 IdP 变量已绑定为 `i`，P 用 `pk(i)` 验证签名——验证通过。
**A、B、IdP 此时全部处于步骤 0，完全未参与。**

```
步骤②  P -> i: {f3,{f2,x42,x41,x39,x210,x211}_inv(pk(i)),NPreq(1)}_inv(pk(x39))
```
P 接受伪造证书，生成新鲜数 `NPreq(1)`，将请求嵌套签名后发给"B"。
对应协议 M4：`P->B: {f3({f2(A, B, P, ReqA, N_A)}inv(pk(IdP)), N_P_req)}inv(pk(P))`。
入侵者在网络上截获这条消息（Dolev-Yao 模型中入侵者控制所有网络流量）。

```
步骤③  i -> P: {f4,x313}_(pk(x39))
```
入侵者冒充 B，用 P 的公钥加密一个**自己选定的值** `x313` 发给 P。
对应协议 M5：`B->P: {Photos}pk(P)`。
P 用 `inv(pk(P))` 解密，接收了"Photos = x313"。

```
步骤④  i 知道 x313
```
因为 x313 是入侵者自己选的，入侵者当然知道其值。
**违反目标：`Photos secret between B,P`**（B 从未参与，P 收到的是假照片）。
。

#### 根本原因分析

**原因一（主要）：IdP 身份未固定绑定**

P 的初始知识为 `P: A,B,P,IdP,pk(B),pk(P),pk(IdP),inv(pk(P))`。
其中 `IdP` 是一个可变的 Agent 变量。在 OFMC 的 Dolev-Yao 模型中，入侵者 $i$ 本身也是合法代理，拥有 `pk(i)/inv(pk(i))`。当 P 角色实例化时，`IdP` 变量可以被绑定为任意代理——包括 $i$。一旦 `IdP = i`，入侵者就能签出 P 认为合法的"IdP 证书"。

**原因二（次要）：B 的响应未与 P 的请求绑定**

B 发送 `{Photos}pk(P)` 时，消息中不包含 P 发出的 `N_P_req`。P 无法验证收到的 Photos 是否真的来自对 M4 的响应，任何人都可以用 `pk(P)` 构造一条消息发给 P。

**攻击的本质**：整个攻击仅在入侵者和 P 之间完成，完全绕过了诚实的 A、B 和 IdP。协议依赖的"信任链"（A→IdP→P→B）在没有固定 IdP 身份的情况下，可以被入侵者单独短路。

#### 最终解决方案

**一：修复身份提供者IdP**

将身份提供者的名称从IdP改为idp，并被视为一个固定代理。这可防止入侵者在验证过程中充当身份提供商角色，同时体现了具有单一可信身份提供商的预期架构。

**二：将B与P之间的通信加密**

将最终B发给P的消息加入B的签名之后用P的公钥进行加密

**三：添加角色约束**

引入约束
```
where B!=P
```
这防止角色B和P被实例化为同一代理。此类情况不切实际，且在模型检查过程中可能导致人为攻击。

**四：简化消息内容**

与前一版本相比，协议消息在保留必要绑定的同时进行了简化：
```
f3(B, P, {f2(B, P, ReqA, N_A)}inv(pk(idp)), N_P_req)
f4(B, P, N_P_req, Photos)
```
身份标识和随机数确保了适当的会话绑定，并防止重放攻击或混淆攻击。

#### 主协议 OFMC 最终完整输出
```
SUMMARY:
  NO_ATTACK_FOUND
GOAL:
  as specified
DETAILS:
  BOUNDED_NUMBER_OF_SESSIONS
BACKEND:
  Open-Source Fixedpoint Model-Checker version 2024
STATISTICS:
  TIME 91359 ms
  parseTime 0 ms
```


## 4. 特殊任务：证明协议是 Type-Flaw Resistant

**目标**：证明你的协议（主协议 + 子协议）是类型无缺陷的（Type-Flaw Resistant）。

**主协议证明**

**Step 1：提取协议的最简消息模式 SMP**

将所有消息抽象为最一般模式（只保留结构、格式标签、加密结构，用变量表示参数）：

1. m1​={f1(X1​,X2​​,N1​,N2​,W1​)}pk  
2. m2​={f2(X1​,X2​​,N1​,N2​)}sk​   
3. m3​={f2(X1​,X2​​,N1​,N2​)}sk​  
4. m4​={f3(X1​,X2​​,M1​,N3​)}sk​  
5. m5​={{f4(X1​,X2​​,N3,N4​)}sk​}pk 

**SMP = { m₁, m₂, m₃, m₄, m₅ }**

**Step 2：两两检查是否可合一（unify）**

1. m₁ 与其他所有消息  
- m₁是单层公钥加密的 f1 结构（5 参数），其余为私钥签名 / 嵌套加密结构   
- 格式标签、加密类型均不同 
2. m₂ 与 m₄  
- m₂：内部 f2，4 个基础参数  
- m₄：内部 f3，含加密子项的 4 参数 
格式标签、参数类型均不同，不可合一  
3. m₂ 与 m₅  
- m2​ 是单层私钥签名  
- m5​ 是私钥签名 + 公钥加密的嵌套结构  
不可合一  
4. m₄ 与 m₅  
- m4​ 是单层私钥签名 
- m5​ 是私钥签名 + 公钥加密的嵌套结构  
不可合一  
5. m₂ 与 m₃  
- 结构、格式标签、参数完全一样  
- 可以合一，且类型完全相同  

**Step 3：验证类型一致性**   
- 所有可合一的消息对：只有 m₂ 与 m₃，它们类型相同（都是 f2 结构的签名消息）。   
- 所有不可合一的消息对：自然满足 Type‑Flaw Resistant 要求。

**子协议证明**

**Step 1：提取协议的最简消息模式 SMP**

将所有消息抽象为最一般模式（只保留结构、格式标签、加密结构，用变量表示参数）：

1. m1​=f1(X1​,X2​​,N1​)  
2. m2​={f2(X1​,X2​,T1​,N1​​)}sk​ 

**SMP = { m₁, m₂ }**

**Step 2：两两检查是否可合一（unify）**

只有一对：m₁ vs m₂  
- m1​=f1(X1​,X2​,N1​)明文，顶层格式：f1，3 个参数   
- m2​={f2(X1​,X2​,T1​,N1​)}sk​私钥签名加密，顶层格式：f2，4 个参数

**结论：**  
**不存在任何合一子 σ 能让 m₁ = m₂** 

**Step 3：验证类型一致性**   
- 两条消息 不可合一   
- 满足 Type-Flaw Resistant 的条件
---

