# Project on Information Flow — Design Document
# 信息流项目 — 设计文档
**Role: Designer (architecture, policy, and lattice)**
**角色:设计师(架构、策略、Lattice)**
**Course: 02244 Logic for Security, Spring 2026**

> **Scope.** This is the **Designer** part of the report. It fixes the system
> architecture and the security framework; the API commands and their
> per-command security arguments live in a sibling document `api.md`.
>
> **范围。** 本文档是报告的"设计师"部分,负责定下系统架构和安全框架;
> 具体的 API 命令以及每条命令的安全论证由另一份 `api.md` 完成。
>
> Every methodological choice is taken from one of the three required papers:
> 所有方法学选择只来自这三篇必读论文:
>
> - **Denning & Denning, 1977** — *Certification of Programs for Secure Information Flow* (Lecture 1).
> - **Volpano, Smith, Irvine, 1996** — *A Sound Type System for Secure Information Flow* (Lecture 2).
> - **Myers & Liskov, 1997** — *A Decentralized Model for Information Flow Control* (Lecture 3).
>
> No custom variant of information flow analysis is invented. The only
> adaptations are extensions to programming constructs not covered in the
> originals (arrays and procedures, à la the Denning-challenge in Lecture 2).
>
> 没有自创任何信息流变体。唯一的改造是把这些方法套到论文没覆盖的语言结构
> 上(数组和过程,做法见 Lecture 2 中的 "Denning-challenge")。

---

## 1. Application Scenario / 应用场景

We instantiate the project in the **hospital scenario** from the assignment text.
我们用作业里的**医院场景**来实例化整个系统。

**Why this scenario / 为什么选医院:**

- It is the canonical motivating example for DLM (Lecture 3, Fig. 1).
  DLM 论文自己就是用医院做例子的。
- It forces multiple data owners (each patient owns their own record), which
  is exactly what a fixed two-point lattice cannot express.
  它天然有多个数据 owner(每个病人是自己病历的 owner),这是 `{Low,High}` 这种两级 lattice 表达不了的。
- It motivates **declassification** (anonymised statistics released to
  researchers), which is the one feature that *requires* DLM.
  它需要降密(匿名统计给研究员看),而降密在三篇论文里**只有 DLM 才能做**。

> **大白话:** 选医院是因为它"用得上"我们设计文档里所有的工具。如果选个简单
> 的相册服务,我们做的很多东西就成了花架子,15 页凑不出来。

---

## 2. Participants and Roles / 参与者与角色

In the DLM the set of *principals* is the abstract set `P` from which owners
and readers are drawn (Lecture 3, slide 10).
DLM 里 *principal*(主体)是一个抽象集合 `P`,owner 和 reader 都从这里取。

We fix the following principals / 我们把主体集固定为:

| Principal 主体 | Symbol 符号 | Acts as owner of … 拥有 | Typically reads … 通常能读 |
|---|---|---|---|
| Hospital 医院 | `H` | hospital-internal records 院内资料 | data of patients in its care 自己病人的数据 |
| Patient 病人 | `p ∈ Pt` | their own medical record 自己的病历 | their own record 自己的病历 |
| Doctor 医生 | `d ∈ Dr` | treatment notes they author 自己写的诊疗记录 | records of their patients 经授权的病人记录 |
| Researcher 研究员 | `r ∈ Rs` | — | declassified statistics only 仅匿名后的统计 |
| Statistics service 统计服务 | `S` | aggregate counters 聚合计数器 | declassified aggregates 降密后的聚合 |
| Server (TCB) 服务器 | `Srv` | — | nothing — see §3 什么都不读,见 §3 |

**Delegation / 授权委托.** Patients delegate authority to the hospital with
the `acts_for` relation (`H acts_for p` after the patient signs an admission
form). Doctors get `H acts_for d` while employed. Every other process runs
**without authority by default**, exactly as in Lecture 3 slide 14.

病人通过 `acts_for` 关系把权限委托给医院:`H acts_for p` 在病人签住院同意书后建立;
医生在职期间有 `H acts_for d`。**默认所有进程没有任何权限** —— 这正是 Lecture 3
slide 14 的设定。

### Trade-off / 取舍

| Option 方案 | 中文 | Verdict 结论 |
|---|---|---|
| 2 principals (Doctor / Patient) | 只设两个主体 | ❌ 一个 `High` 把所有病人压成一类,做不到"只有 Alice 的医生能读 Alice 病历" |
| No principals (just Low/High) | 不设主体,直接 Low/High | ❌ 没 owner,根本不能 declassify |
| **Multi-principal as above ✓** | **多主体(本方案)** | ✅ 表达每病人独立隐私;支持降密 |

> **大白话:** "principal" 听起来抽象,你就把它当成"系统里的角色 ID"。每个病人
> 都是一个独立的 ID,因为每个人的隐私要分开管。如果不分开,系统等于只有一个
> 大保险箱,所有病人共用一把钥匙 —— 显然不行。

---

## 3. Security Goals / 安全目标

### 3.1 Confidentiality (primary) / 机密性(主要目标)

**Goal C.** For every API command, an attacker who controls dishonest users
and/or uploaded programs cannot obtain any information about a value with
label `s` unless the attacker is in `EffectiveReaders(s)` (Lecture 3 slide 12).

**目标 C。** 对每条 API 命令:即便用户和上传的程序是恶意的,攻击者也只能看到
他在 `EffectiveReaders(s)` 名单里的那些数据。

We make this precise via the **Non-Interference Theorem** of Volpano et al.
(Lecture 2 slide 6): if a program type-checks under our typing rules, then
any two executions whose high-confidentiality inputs differ produce
indistinguishable low-confidentiality outputs.

我们用 Volpano 等人的 **Non-Interference 定理**(Lecture 2 slide 6)把这个目标
精确化:如果一段程序通过类型检查,那么"两次执行只要 Low 输入相同,Low 输出
就一定相同"—— High 数据怎么变,Low 观察者都看不出来。

**Trust boundary / 可信边界.** The only component we trust is the **Server
type-checker** (`Srv`). Users, doctors, patients, and uploaded programs are
all potentially dishonest. Goal C therefore reduces to:

整个系统里**只信服务器的类型检查器**(`Srv`)。用户、医生、病人、上传的程序都
默认不可信。Goal C 拆成两件事:

1. The Server faithfully implements the typing rules of Volpano §4.
   服务器忠实地跑 Volpano §4 的类型规则。
2. Every declassification is justified by an `if_acts_for` whose authority
   chain is checked against the explicit `acts_for` table.
   每次 declassify 都被一个 `if_acts_for` 包住,且授权链可以在 `acts_for` 表里查到。

### 3.2 Integrity (secondary) / 完整性(次要目标,我们也做)

DLM gives integrity for free as the **dual** of confidentiality
(Myers–Liskov §6; Lecture 3 slide 9: *"except for declassification this is
standard information flow à la Denning"*).

DLM 让 integrity 几乎"白送":它就是 confidentiality 的**对偶**。
(Lec 3 slide 9 原话:"除了 declassification 这一块,其余都是标准的 Denning 式信息流。")

- A confidentiality label `{o : r₁,…,rₙ}` means *"o allows r₁,…,rₙ to read"*.
  机密标签 `{o : r₁,…,rₙ}` 表示 "o 允许 r₁,…,rₙ 读"。
- An integrity label `{o : w₁,…,wₙ}` means *"o vouches that the value was
  produced by one of w₁,…,wₙ"*.
  完整性标签 `{o : w₁,…,wₙ}` 表示 "o 担保这个值是由 w₁,…,wₙ 之一写的"。

**Order is reversed for integrity / 完整性的顺序反过来**:a value trusted by
*more* writers is *less* contaminated. Bottom of integrity = trusted by everyone;
top = trusted by no one.

完整性的"⊥(最低)"= 谁都信(干净);"⊤(最高)"= 谁都不信(脏)。这刚好和
机密性反过来。

**Goal I.** No malicious user / program can cause a value labelled with
integrity `i` to be written from an input whose integrity is below `i`.

**目标 I。** 恶意用户/程序不能用一个完整性比 `i` 低(更脏)的输入去写一个
完整性是 `i` 的变量。

### Trade-off — why include integrity / 为什么也做完整性

| | Pro 优点 | Con 缺点 |
|---|---|---|
| **Add integrity ✓** | 医院场景没 integrity 没意义(否则陌生人能改诊断结论)。dual 构造完全机械,几乎免费复用机密性的全部机制。 | 每个变量带两个标签;每条 typing rule 跑两遍;证明大约长一倍。 |
| Skip integrity | 报告短一点。 | 作业明确说"如果也考虑 integrity ……" —— 多做一点是加分项;医院场景几乎要求做。 |

> **大白话:** confidentiality 管"谁能看",integrity 管"信谁写"。一个保险柜光锁
> 着没用,还得知道里面装的是不是真东西。两个我们都做。

### 3.3 Out of scope / 不做的事

Following Lecture 4 slides 8–10, we **do not** attempt to prevent:

按 Lecture 4 slide 8–10,我们**不**处理:

- **Timing channels / 时序信道** (e.g. RSA timing attack of Brumley & Boneh).
- **Termination channels / 终止信道** — Volpano's non-interference is
  *termination-insensitive*. Volpano 的 Non-Interference 是"非终止敏感"的。
- **Other covert channels / 其他隐蔽信道.**

We state this limitation explicitly; closing those channels is not in scope
for any of the three required papers.
我们把这条限制写明:三篇论文都不覆盖这些通道,所以我们也不假装能堵。

---

## 4. Design Choices and Trade-offs / 设计选择与取舍

This section lists every binary choice we made, the alternative we rejected,
and the reason. Option names are taken verbatim from the assignment or
lectures.

本节列出每一个二选一的选择,被拒方案,以及原因。选项名都和作业原文/课件一致。

---

### 4.1 Fixed lattice vs. user-defined lattice / 固定 lattice vs. 用户自定义

**Choice / 选择:** a single global lattice in DLM style (Lecture 3 slide 10).
The lattice is `(P ↛ PowerSet(P), ⊑, ⊔, ⊓)` with `P` the set of all
principals enrolled on the server.

整个系统**用一个全局的 DLM lattice**(Lec 3 slide 10):载体是 `P ↛ PowerSet(P)`
(从主体到主体集合的部分映射),`P` 是服务器上所有注册主体的并集。

| Option 方案 | 中文 | 评价 |
|---|---|---|
| Per-user custom lattice | 每个用户自己定 lattice | ❌ 不同用户的 lattice 怎么合并三篇论文都没说;自创 = 作业明令禁止 |
| Fixed `{Low,High}` Denning lattice | 固定两级 lattice | ❌ 表达不了"每病人独立隐私",且没 owner,不能 declassify |
| **DLM lattice ✓** | **DLM lattice(本方案)** | ✅ 多 owner / 多 reader 一次表达;`⊑ ⊔ ⊓` 都有定义;支持 declassify |

> **大白话:** 自创 lattice 老师会扣分(明文禁止);两级 lattice 太弱(医院场景
> 用不了);DLM 是唯一既合规又够用的。

---

### 4.2 Black-box vs. white-box programs / 黑盒程序 vs. 白盒程序

**Choice / 选择:** **white-box only.** Every program a user wants to run on
the server must be uploaded **as source code** in our small imperative
language, with security labels on every variable. The server runs the Volpano
type checker before executing.

**只接受白盒。** 用户要在服务器上跑的程序必须以**源码**形式上传,每个变量带
安全标签;服务器先跑 Volpano 类型检查,通过了才运行。

| Option 方案 | 中文 | 评价 |
|---|---|---|
| Pure black-box | 纯黑盒(只给二进制) | ❌ Lec 3 slide 9 规定:黑盒输出要打成"所有输入标签的 join"。结果是任何函数处理 `{p:p,H}` 后输出都还是 `{p:p,H}`,只有病人和医院能看 —— 几乎没用 |
| **White-box only ✓** | **只白盒(本方案)** | ✅ 拿到 Volpano 的 Non-Interference 定理;服务器能数学证明:即使上传者恶意也不会泄漏 |
| Hybrid (white-box may call certified black-box library) | 白盒调用经认证黑盒库 | ❌ 我们没有"认证黑盒"的工具(三篇论文里没给),所以这条路走不通 |

> **大白话:** 黑盒等于把整袋米倒进一个大池子,啥也分不出来 —— 太粗;混合需要
> 我们没学过的工具;只剩白盒。代价是用户得交源码,而且只能用我们这个简单的
> 小语言。

---

### 4.3 Static vs. runtime enforcement / 静态检查 vs. 运行时监控

**Choice / 选择:** **static checking at upload time** (Volpano §3 / Lec 2
slides 8–9). The program is rejected *before* it ever runs.

**上传时做静态类型检查**。不通过的程序直接拒绝,从来不会被执行。

| Option 方案 | 中文 | 评价 |
|---|---|---|
| Runtime monitor | 运行时监控 | ❌ Lec 4 slide 8 自己证了:监控器在违反规则时"停下来"这件事本身就是可观察的,会泄漏 High 信息 |
| **Static type system ✓** | **静态类型系统(本方案)** | ✅ Sound;拒绝发生在执行之前,与 High 输入无关,因此不会泄漏 |

> **大白话:** "运行到一半发现不对,停下来" 看起来很安全,但"它停了"本身就是
> 一条信息 —— 比如 "如果 `y > 0` 程序就会停",那观察者知道程序停了就等于知道
> `y > 0`。所以必须在运行前就判完。

---

### 4.4 Volpano vs. Denning rules / 用哪种规则

**Choice / 选择:** **Volpano's typing rules** as the *enforcement* mechanism
(Lec 2 slides 8–9), with **Denning-style derivations** for constructs Volpano
did not write down (arrays, procedures — see Lec 2 slides 3–4 *Challenges
for Denning's*).

**用 Volpano 的类型规则做实际检查**;Volpano 没写过的语法(数组、过程)用
Denning 的方法补上。

The two are equivalent on the common fragment (Lec 2 slide 6:
*"Essentially the same approach as Denning and Denning … but represented as
a type system"*).

两者在公共部分等价(Lec 2 slide 6 原话:"和 Denning 本质一样,只是写成类型
系统")。

**Why Volpano as the *primary* / 为什么主用 Volpano:**

- 类型系统配套 **Non-Interference 定理**(Goal C 直接归约到这里);
- 类型推导更适合在服务器上机械实现,比 Denning 的 AST 走查更工整;
- `IF` / `WHILE` 规则里的 `τ' ⊑ τ` 边条件天然把 Denning 的"语句安全类"和
  隐式流约束一并管掉。

For arrays `A[E₁] := E₂` and procedure `call p(E,var)` we use the rules
derived in Lec 2 slides 3–4:

数组和过程的规则照搬 Lec 2 slides 3–4:

```
A[E₁] := E₂        ⇒  E₁ ⊔ E₂ ⊑ A
call p(E,var)      ⇒  E ⊑ var_in,  var_out ⊑ var
```

These were derived from Denning's framework; we do not invent any new rule.
这些是从 Denning 框架里推出来的,我们没自创新规则。

> **大白话:** Volpano = Denning 的"现代版打包"。它给了一个数学定理,我们整个
> 安全证明就靠它撑着。Denning 的好处是写法直观,在 Volpano 没覆盖的地方拿来
> 顶上正合适。

---

### 4.5 Declassification: yes or no / 要不要降密

**Choice / 选择:** **yes**, but only via DLM's `if_acts_for` + `declassify`
(Lec 3 slides 13–14).

**做**,但只能用 DLM 的 `if_acts_for` + `declassify`。

The declassification rule is exactly Lec 3 slide 13:

降密规则严格按 Lec 3 slide 13:

> An owner `o` can declassify their data only by (a) **adding readers** for
> owner `o`, or (b) **removing the owner `o`**.
>
> owner `o` 想 declassify 自己的部分,只能(a)给自己的 reader 列表加人,
> 或(b)把自己从 owner 列表里移除。

A `declassify(e, s')` step type-checks only inside an `if_acts_for(X,Y)` whose
authority `Y` is justified against the `acts_for` table.

`declassify(e, s')` 必须包在某个 `if_acts_for(X,Y){…}` 里面,而且 `Y` 的
授权必须能在 `acts_for` 表里查到。

| Option 方案 | 中文 | 评价 |
|---|---|---|
| No declassification | 不做降密 | ❌ Researcher 这个角色就废了;医院场景做不下去 |
| **DLM declassification ✓** | **DLM 降密(本方案)** | ✅ 三篇论文里**只有这条路**合法 |
| Custom declassification predicate | 自创一个降密谓词 | ❌ **作业禁止** |

> **大白话:** 没有降密 → 研究员永远拿不到任何数据。自创降密 → 老师扣分。
> 唯一选项就是 DLM 那一套 `if_acts_for + declassify`。

---

### 4.6 Source language / 白盒程序的语言

**Choice / 选择:** the Volpano core language extended with arrays and
procedures (and the DLM's `if_acts_for` / `declassify`).

**Volpano 核心语言 + 数组 + 过程 + DLM 的 `if_acts_for` / `declassify`。**

```
e ::= x | n | e op e                        (Lec 2 slide 7)
c ::= x := e | c ; c | if e then c else c | while e do c
    | input x from f | output e to f          (Lec 1 slide 20)
    | A[e] := e | call p(e, x)                (Lec 2 slide 4)
    | if_acts_for(X, Y) { c }                  (Lec 3 slide 14)
    | x := declassify(e, s)                    (Lec 3 slide 13)
```

Records `record [field : T{label}, …]` are added the obvious way (Lec 3
slide 3, the Login program).

记录类型按 Lec 3 slide 3 的样子加上去。

We **reject** richer languages (closures, higher-order functions, exceptions,
concurrency) because none of the three papers cover them and we cannot
extrapolate the rules.

我们**拒绝**更强的语言特性(闭包、高阶函数、异常、并发)—— 三篇论文不覆盖
这些,而我们不能擅自推规则。

> **大白话:** 我们用的语言只比"小学生 BASIC"多一点点。不能用是因为我们没有
> 工具去证它的安全性。够用就行。

---

### 4.7 Confidentiality only vs. confidentiality + integrity

Argued in §3.2; we include both. The label of a variable is therefore a
**pair** `(s_C, s_I)` — confidentiality + integrity, each from a DLM lattice
but ordered dually. Every typing rule fires once on each component.

见 §3.2,我们两个都做。每个变量的标签是一对 `(s_C, s_I)`,机密性和完整性
各一个 DLM lattice(顺序对偶)。每条类型规则在两个分量上各跑一次。

---

## 5. The Security Lattice — formal definition / 安全 Lattice 形式定义

We give the lattice precisely, following Lec 3 slides 10–11 verbatim.
本节严格照 Lec 3 slides 10–11 的写法。

### 5.1 Confidentiality lattice `L_C` / 机密性 lattice

**Carrier / 载体:** `L_C = P ↛ PowerSet(P)` — partial maps from principals to
sets of principals. We write
`s = {o₁ : r₁,₁,…,r₁,k₁ ; … ; oₙ : rₙ,₁,…,rₙ,kₙ}`,
read as: "for every owner `oᵢ`, `oᵢ` allows `rᵢ,₁,…,rᵢ,kᵢ` to read".

读作:"对每个 owner `oᵢ`,`oᵢ` 允许 `rᵢ,₁,…,rᵢ,kᵢ` 读"。

**Auxiliary / 辅助函数** (Lec 3 slide 10):
- `Owners(s) = dom(s)`.
- `Readers(s, p) = s(p)` if `p ∈ Owners(s)`, else `Readers(s, p) = P`.
- `EffectiveReaders(s) = ⋂_{o ∈ Owners(s)} Readers(s, o)` — the principals
  who may *actually* read, i.e. allowed by **every** owner (Lec 3 slide 12).
  实际能读的人 = 所有 owner 都点头的那些人(交集)。

**Order, join, meet / 顺序、并、交** (Lec 3 slide 11):
- `s₁ ⊑ s₂` iff `Owners(s₁) ⊆ Owners(s₂)` and ∀`o ∈ Owners(s₁)`,
  `Readers(s₁, o) ⊇ Readers(s₂, o)`.
  (s₂ owner 更多 + 每个 owner 给的权限更窄 → s₂ 更"严格")
- `Owners(s₁ ⊔ s₂) = Owners(s₁) ∪ Owners(s₂)`,
  `Readers(s₁ ⊔ s₂, o) = Readers(s₁, o) ∩ Readers(s₂, o)`.
- `Owners(s₁ ⊓ s₂) = Owners(s₁) ∩ Owners(s₂)`,
  `Readers(s₁ ⊓ s₂, o) = Readers(s₁, o) ∪ Readers(s₂, o)`.

**Bottom / 底.** `⊥_C = { }` — no owners, hence `EffectiveReaders(⊥_C) = P`
(anyone may read). This is the **public** class.
没 owner = 任何人都能读 = 公开。

**Top / 顶.** A label `{p : ∅}` for any principal `p`: `EffectiveReaders` is
empty — nobody can read.
某个 owner 一个 reader 都不给 = 没人能读。

### 5.2 Integrity lattice `L_I` / 完整性 lattice

Same carrier with **dual** ordering:
载体一样,顺序**对偶**:

- `s₁ ⊑_I s₂` iff `Owners(s₁) ⊆ Owners(s₂)` and ∀`o ∈ Owners(s₁)`,
  `Writers(s₁, o) ⊆ Writers(s₂, o)`.

`Writers(s, o)` = "owner `o` 担保的合法写者集合"。直觉:更多 owner 担保 +
每个 owner 给的写者集越窄,值越可信。

**Bottom / 底.** `⊥_I = { }` — fully trusted (no constraint). Corresponds to
"Low-integrity" in Denning's dual reading (Lec 1 slide 12 reversed).
完全可信(没人提任何要求)。

**Top / 顶.** `{p : P}` — fully untrusted (everyone could have written it).
完全不可信(谁都可能写过)。

### 5.3 Variable labels / 变量标签

Every variable, file, array, and procedure parameter carries a pair
`(s_C, s_I)`. A flow `e ⇝ x` is allowed iff
每个变量、文件、数组、过程参数都带一对 `(s_C, s_I)`。流 `e ⇝ x` 合法 ⟺

```
underline(e)_C ⊑_C underline(x)_C   ∧   underline(x)_I ⊑_I underline(e)_I
```

The integrity component is reversed because integrity flows *the other way*:
a *lower-integrity* expression must not write into a *higher-integrity*
variable.

完整性反过来是因为它流的方向相反:更脏的表达式不能写进更干净的变量。

### 5.4 Fixed principal hierarchy / 固定的主体层次

```
P = {Srv} ∪ {H} ∪ Pt ∪ Dr ∪ Rs ∪ {S}
```

The `acts_for` relation is populated by the user-management layer (out of
scope — comes from Assignment 1's authentication).

`acts_for` 关系由用户管理层(Assignment 1 的认证层)维护,本报告范围外。

- New patient `p` registered → `p ∈ Pt`.
- Patient signs admission → `H acts_for p` recorded.
- Doctor `d` employed → `H acts_for d` recorded.
- `r ∈ Rs` and `S` are static.

---

## 6. Summary at a glance / 一图看完

| Question / 问题 | Decision / 决定 | Source / 出处 |
|---|---|---|
| Application 应用 | Hospital 医院 | Assignment §"The Setting" |
| Lattice | DLM, single global, fixed `P` | Lec 3 slides 10–11 |
| Owner / reader semantics | Myers–Liskov verbatim | Lec 3 slide 10 |
| Declassification | `if_acts_for(X,Y){ x := declassify(e, s') }` | Lec 3 slides 13–14 |
| Programs 程序 | White-box only, source uploaded 只白盒 | Assignment §"Your Design" 4th bullet |
| Enforcement 检查时机 | Static type checking 静态 | Volpano §3 / Lec 2 slides 8–9 |
| Typing rules 类型规则 | Volpano core + Denning-style for arrays/procedures | Lec 1 slide 20, Lec 2 slides 3–4, 8–9 |
| Soundness goal 安全保证 | Non-interference (termination-insensitive) | Volpano §5 / Lec 2 slide 6 |
| Confidentiality 机密性 | Yes — primary | Assignment §"Security Goals" |
| Integrity 完整性 | Yes — dual DLM lattice | Lec 3 slide 9 + Myers–Liskov §6 |
| Out of scope 不做 | timing/termination/covert channels | Lec 4 slides 8–10 |

---

## 7. Plain-language recap — why every choice / 大白话总结:每个选择为什么

> 这一节就是把上面所有 trade-off 用一段连贯的话讲清楚,方便组里另外两个人和
> 老师 5 分钟内抓住"我们为什么这么设计"。

**1. 为什么用 DLM(而不是 Low/High)?**
医院里每个病人的隐私是分开的。两级 lattice 把所有人压成一类,做不到"只有
Alice 的医生能读 Alice 病历"。而且 declassification 必须有 owner 才能做
(只有 owner 才有资格"放行"自己的数据)。要做研究员匿名统计这一档子事,
没 DLM 就没法做。

**2. 为什么只接白盒(不接黑盒/混合)?**
- 黑盒程序我们看不到代码,只能按 DLM 规则把输出标成"所有输入的 join",结果
  几乎等于"医院 + 病人专属",研究员永远读不到 → 没意义。
- 混合方案需要"经认证的黑盒库",但我们没有任何工具能给黑盒发认证 ——
  三篇论文都没讲。
- 白盒虽然要求用户交源码、只能用我们这个简单语言,但作为代价我们能拿到
  Volpano 的 Non-Interference 定理 —— 这是整个安全论证的基石。

**3. 为什么静态(不在运行时监控)?**
"运行到一半发现违规就停下" 看起来灵活,但**"停了"这件事本身就泄漏信息**。
比如 "如果 `y > 0` 就会停",观察者看到停了就推出 `y > 0`。Lec 4 slide 8
原话明示这个问题。所以必须在执行之前就判完,这就是静态。

**4. 为什么 Volpano 主、Denning 辅?**
两者数学上等价。Volpano 写成类型系统,有 Non-Interference 定理(我们的安全
保证就来自这个定理),也好机器化。但 Volpano 没写数组和过程,这块用 Denning
的方法补上 —— 都是合规的 "course material",没自创。

**5. 为什么做 declassification?**
不做就没法把研究员这个角色装进系统(医院场景的核心需求)。做就只能用
DLM 的 `if_acts_for + declassify` —— 作业明文规定。

**6. 为什么连 integrity 一起做?**
机密性管"谁能看",完整性管"信谁写"。医院里光锁住数据没用,还得防止陌生
人乱改诊断。DLM 完整性是机密性的对偶,机制完全复用,代价是证明长一倍 ——
但作业把它列为加分项,值得做。

**7. 为什么不管 timing / termination 漏洞?**
三篇论文都不管。Volpano 的定理本身就是"非终止敏感"的。我们老老实实写明
不在范围内,而不是假装能堵 —— 否则没法证。

---

## 8. Hand-off — what the API author needs / 给 API 作者的接口

The following are **fixed inputs** for the API/Proof author / 这些是你那份
`api.md` 的"输入参数",别再改:

1. The set `P` and the `acts_for` relation are server state.
   `P` 和 `acts_for` 由服务器维护。
2. Every API command must accept *labelled* arguments and return *labelled*
   results — both confidentiality and integrity labels.
   每条 API 的参数和返回值都带双标签。
3. An API command that uploads code triggers Volpano type-checking with the
   array/procedure extensions of §4.6; if the program does not type-check,
   the server returns `ERR_INFOFLOW` and never executes it.
   上传程序的命令触发类型检查;不通过 → `ERR_INFOFLOW` 拒绝。
4. Every `declassify` inside a user program must appear inside an
   `if_acts_for(X,Y)` whose authority `Y` is in the `acts_for` table.
   每个 `declassify` 必须包在合法的 `if_acts_for` 里。
5. Goal C reduces to citing **Volpano Non-Interference**; Goal I reduces to
   the dual.
   Goal C 引用 Volpano 的 Non-Interference 定理;Goal I 用对偶。

---

## References / 参考文献

1. D. E. Denning, P. J. Denning. *Certification of programs for secure
   information flow*. CACM 20(7), 1977. — Lecture 1.
2. D. Volpano, C. Smith, C. Irvine. *A sound type system for secure
   information flow*. JCS 4(3), 1996. — Lecture 2.
3. A. C. Myers, B. Liskov. *A decentralized model for information flow
   control*. SOSP 1997. — Lecture 3.
4. S. Mödersheim. Lecture slides for 02244, weeks 8–11 (Denning, Volpano,
   Myers, Information Leakage), DTU 2026.
