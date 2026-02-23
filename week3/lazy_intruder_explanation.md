# Lazy Intruder：理论详解

## 1. 背景：为什么需要 Lazy Intruder？

### 1.1 Dolev-Yao 模型

在形式化安全协议分析中，我们使用 **Dolev-Yao 模型** 描述入侵者的能力：

- 消息是代数项（algebraic terms），例如 `{A,B}pk(X)`
- 入侵者**完全控制网络**：可以拦截、篡改、伪造、重放任意消息
- 入侵者本身也是一个合法代理，拥有自己的公私钥对 `pk(i) / inv(pk(i))`
- 入侵者的能力由一组**推导规则**精确定义

分析协议安全性本质上是在问：

> **入侵者能否利用自己的能力，破坏协议的安全目标（如机密性、认证性）？**

### 1.2 朴素搜索的困境

最直接的分析方法：枚举入侵者每一步可能发送的所有消息，构建搜索树，看是否能到达攻击状态。

**问题：搜索空间是无限的。**

入侵者知识库 $K$ 里的项可以无限嵌套组合：

$$\{A\}_{pk(B)}, \quad \{\{A\}_{pk(B)}\}_{pk(C)}, \quad \{\{\{A\}_{pk(B)}\}_{pk(C)}\}_{pk(D)}, \quad \ldots$$

这样的暴力搜索永远无法终止，实际工具无法使用。

---

## 2. Lazy Intruder 的核心思想

### 2.1 关键观察

协议中每个诚实代理在**接收消息**时，都有一个固定的**期望格式（pattern）**。

例如，B 在等待 P 的转发请求时，期望收到的格式是：

$$\Big\{\{A,B,P,ReqA,N_A\}_{inv(pk(IdP))},\ N_{P\_req}\Big\}_{inv(pk(P))}$$

这个格式是**由协议结构决定的，是有限的**。

### 2.2 策略转换

Lazy Intruder 把问题反转：

| 朴素方法                       | Lazy Intruder                                                          |
| ------------------------------ | ---------------------------------------------------------------------- |
| 问："入侵者能发什么？"（无限） | 问："为了满足诚实代理的期望，入侵者需要构造什么？他能构造吗？"（有限） |
| 主动枚举所有消息               | 被动验证是否可构造                                                     |
| 搜索空间无限                   | 搜索空间有限                                                           |

> **核心原则：入侵者是"懒惰的"——他只在被迫需要发送某条消息时，才去检查自己的知识库能否构造出该消息。**

---

## 3. 形式化定义

### 3.1 入侵者知识库

定义 $K$ 为入侵者当前已知的所有项的集合。

初始知识库：
$$K_0 = \{\text{公开信息}\} \cup \{\text{入侵者自己的密钥}\}$$

每次入侵者截获一条消息 $m$，更新知识库：
$$K_{n+1} = K_n \cup \mathsf{analyze}(m,\ K_n)$$

### 3.2 推导关系 $K \vdash t$

记作"入侵者从知识库 $K$ 可以推导（构造）出项 $t$"，由以下规则归纳定义：

**① 公理规则（Axiom）**——已知的直接可用：
$$\frac{t \in K}{K \vdash t}$$

**② 组合规则（Composition）**——把已知的拼在一起：
$$\frac{K \vdash t_1 \quad K \vdash t_2}{K \vdash (t_1,\ t_2)}$$

$$\frac{K \vdash m \quad K \vdash k}{K \vdash \{m\}_k}$$

**③ 分析规则（Analysis）**——从已知消息中拆解子项：
$$\frac{K \vdash \{m\}_k \quad K \vdash k^{-1}}{K \vdash m}$$

$$\frac{K \vdash (t_1,\ t_2)}{K \vdash t_1} \qquad \frac{K \vdash (t_1,\ t_2)}{K \vdash t_2}$$

其中 $k^{-1}$ 是 $k$ 的解密密钥：
- 对称加密：$k^{-1} = k$
- 非对称加密：$k^{-1} = inv(k)$（私钥解密公钥加密；公钥验证私钥签名）

---

## 4. Lazy Intruder 算法

### 4.1 协议执行模型

协议执行是一个**有序事件序列**：

$$e_1,\ e_2,\ \ldots,\ e_n$$

每个事件的类型：
- $\mathsf{Send}(\text{sender},\ \text{receiver},\ m)$：某代理发送消息 $m$
- $\mathsf{Recv}(\text{agent},\ \text{pattern})$：某诚实代理期望接收符合 pattern 的消息

### 4.2 算法流程

```
初始化：K = K₀（入侵者的初始知识）

对协议事件序列中的每一步：

  情况A：诚实代理发送消息 Send(honest, _, m)
      → 入侵者截获 m
      → 更新：K = K ∪ analyze(m, K)

  情况B：诚实代理等待接收 Recv(honest, pattern)
      → 入侵者需要构造 pattern 发给该代理
      → 检查：K ⊢ pattern ？
          如果 YES → 路径合法，继续执行
          如果 NO  → 此路径不可达，剪枝，回溯
```

### 4.3 符号化处理（Symbolic Filtering）

Pattern 中往往含有**未知变量**，例如诚实 A 生成的新鲜数 $N_A$——入侵者无法预测其具体值。

Lazy Intruder 使用**符号统一（Symbolic Unification）**处理这种情况：

- 用符号变量代替未知的具体值
- 只在推导链真正需要具体值时才实例化
- 将"无限的具体值枚举"转化为"有限的符号约束求解"

---

## 5. 可执行性（Executability）

### 5.1 定义

称协议中的角色 $R$ 是**可执行的（Executable）**，当且仅当：

> 将角色 $R$ 替换为入侵者 $i$，其余所有角色均为诚实代理，存在一个合法的协议执行轨迹，使得 $i$ 能够完成 $R$ 的**所有发送动作**。

形式化地：对于 $R$ 角色中的每一个发送动作 $\mathsf{Send}(R, X, m)$，在该步骤之前入侵者积累的知识库 $K$ 满足：
$$K \vdash m$$

### 5.2 为什么需要证明可执行性？

可执行性是协议分析的**必要前提**：

- 如果某角色不可执行，说明协议设计有误（例如要求代理发送一条自己根本无法构造的消息）
- 如果某角色可执行，说明"入侵者可以完整扮演该角色而不被发现"，协议对该角色的参与者没有任何保护

---

## 6. 应用示例：证明 Week 3 协议中 P 的可执行性

### 角色配置
- P = 入侵者 $i$
- A、B、IdP = 诚实代理

### P 的角色脚本
```
接收 (M3)：{A, B, P, ReqA, N_A}inv(pk(IdP))        ← 来自 A
发送 (M4)：{{A,B,P,ReqA,N_A}inv(pk(IdP)),N_P_req}inv(pk(P))  ← 发给 B
接收 (M5)：{Photos}pk(P)                            ← 来自 B
```

### 入侵者初始知识

$$K_0 = \{\ i,\ A,\ B,\ IdP,\ pk(B),\ pk(i),\ pk(IdP),\ inv(pk(i))\ \}$$

注：扮演 P 时，$pk(P) = pk(i)$，$inv(pk(P)) = inv(pk(i))$。

---

### Step 1：接收 M3

诚实 A 经 IdP 认证后，发给 P（即 $i$）：

$$A \to i :\ \{A,\ B,\ i,\ ReqA,\ N_A\}_{inv(pk(IdP))}$$

- $i$ 没有 $inv(pk(IdP))$，无法解开签名
- 但 $i$ **不需要**解开——将整块密文作为不透明项存入知识库

$$K_1 = K_0\ \cup\ \Big\{\ \{A,B,i,ReqA,N_A\}_{inv(pk(IdP))}\ \Big\}$$

✅ **接收成功**

---

### Step 2：发送 M4

P 需要发送：

$$\Big\{\{A,B,i,ReqA,N_A\}_{inv(pk(IdP))},\ N_{P\_req}\Big\}_{inv(pk(i))}$$

用 Lazy Intruder 检查 $K_1 \vdash$ 该消息：

| 所需材料                            | 来源                | 规则            |
| ----------------------------------- | ------------------- | --------------- |
| $\{A,B,i,ReqA,N_A\}_{inv(pk(IdP))}$ | 直接在 $K_1$ 中     | **Axiom**       |
| $N_{P\_req}$                        | $i$ 自由生成新鲜数  | **Composition** |
| $inv(pk(i))$ 用于签名               | 在 $K_0$ 中         | **Axiom**       |
| 拼接后加密                          | 由 Composition 规则 | **Composition** |

$$K_1 \vdash \Big\{\{A,B,i,ReqA,N_A\}_{inv(pk(IdP))},\ N_{P\_req}\Big\}_{inv(pk(i))}$$

$$K_2 = K_1\ \cup\ \{\ N_{P\_req}\ \}$$

✅ **发送成功**

---

### Step 3：接收 M5

诚实 B 收到 M4 后，向 P（即 $i$）发送照片：

$$B \to i :\ \{Photos\}_{pk(i)}$$

- $inv(pk(i)) \in K_0$ ✅
- **Analysis 规则**：$K_2 \vdash \{Photos\}_{pk(i)}$ 且 $K_2 \vdash inv(pk(i))$ → $K_2 \vdash Photos$

$$K_3 = K_2\ \cup\ \Big\{\ \{Photos\}_{pk(i)},\ Photos\ \Big\}$$

✅ **接收并解密成功**

---

### 结论

$$\forall\ \mathsf{Send}(P, X, m)\ \text{在 P 的角色脚本中}:\ K \vdash m$$

**P 角色是可执行的（Executable）。** $\blacksquare$

---

## 7. 理论保证

### 7.1 完备性（Completeness）

> 如果协议存在攻击，Lazy Intruder 方法**一定能找到**。

这来自于定理：在 Dolev-Yao 模型下，**任何攻击都可以被规范化（normalize）为一个 Lazy Intruder 攻击**，即入侵者只在必要时构造消息，不做多余的计算。

### 7.2 可靠性（Soundness）

> Lazy Intruder 找到的攻击都是**真实有效的攻击**，不存在误报（false positive）。

### 7.3 可终止性（Termination）

> 对于有界会话数（bounded sessions），Lazy Intruder 搜索**一定会终止**。

搜索空间从无限缩减为**多项式级别**，这正是 OFMC 能在毫秒级给出结果的原因。

---

## 8. 总结

```
朴素搜索                          Lazy Intruder
─────────────────────             ─────────────────────
"入侵者能发什么？"                 "诚实代理期望收到什么？"
主动枚举（无限）                   被动验证（有限）
搜索空间 = ∞                      搜索空间 = 协议结构决定
无法实用                          毫秒级完成
```

Lazy Intruder 的本质是：**把对入侵者行为的无限枚举，转化为对协议期望格式的有限可构造性验证。**
