# DTU 02244 Logic for Security
# Project on Information Flow - Consolidated Server Design

Group members: TODO: add names

Resources used: Denning and Denning (1977), Volpano, Smith and Irvine (1996),
Myers and Liskov (1997), lecture1.pdf, lecture2.pdf, lecture3.pdf,
lecture4.pdf, the assignment text ifproject (1).pdf, and internal group
drafts design.md, assignment2.md, and if_report_1.md. AI assistance was used
to consolidate and edit the group drafts; all technical claims should be
checked by the group before submission.

---

## 1. Participants and Roles

Author: Student A

We design the server for the hospital scenario from the assignment. The same
design also works for a personal hosting service, but the hospital setting is
the clearest case because it needs several independent data owners, controlled
sharing, untrusted programs, and explicit declassification for research
statistics.

The set of principals is:

```
P = {Srv, H} union Pt union Dr union Rs union {Stat}
```

where:

- `Srv` is the trusted hosting server. It stores data, checks labels, type-checks
  uploaded programs, and executes approved programs in a sandbox.
- `H` is the hospital. It may own hospital-internal records and may be
  delegated authority by patients.
- `p in Pt` is a patient. Each patient owns their own medical record policy.
- `d in Dr` is a doctor. A doctor may read records only when authorized by the
  relevant labels.
- `r in Rs` is a researcher. Researchers may read only declassified aggregate
  results.
- `Stat` is the statistics service used to compute aggregate results.

Users and uploaded programs are not trusted. A dishonest user may call any API
command with arbitrary parameters. A malicious program may try to leak data
through explicit assignments, implicit control flow, or malicious output labels.
The trusted computing base is limited to the server implementation, its
information-flow type checker, the label store, and the sandbox.

Authentication is assumed to be provided by the secure channel from Assignment
1, as allowed by the project text. The identity provider authenticates users, but
does not become an owner of user data and does not decide information-flow
labels.

---

## 2. Security Goals and Scope

Author: Student A

### 2.1 Confidentiality

The main goal is confidentiality:

For every file or program variable with DLM label `s`, a principal `q` may learn
information about that value only if:

```
q in EffectiveReaders(s)
```

This must hold even if users are dishonest and uploaded programs are malicious.
The guarantee covers explicit flows, such as assigning a private value to a
public output, and implicit flows, such as branching on a private value and then
modifying a public output.

We state this as a DLM-relative non-interference property. For a principal `q`,
two memories are `q`-equivalent if they agree on all variables whose labels
allow `q` to read them. If a program passes the server type check and both
executions terminate, then running it from two `q`-equivalent memories produces
two final memories that are still `q`-equivalent.

This is the Volpano non-interference theorem instantiated with DLM labels.

### 2.2 Integrity

Integrity is discussed but not enforced in this design.

The assignment allows a design to focus only on confidentiality. We make that
choice because the most important grading priority is a small design that can be
proved precisely. Adding integrity would require a second DLM label on every
file and variable, dual type-checking rules for every command, and a second
proof argument for each API command. That extension is natural, but it doubles
the proof surface and makes it harder to keep the report within 15 pages.

Security consequence: this report does not prove that low-integrity input cannot
influence high-integrity output. A complete production system should add the
integrity DLM from Lecture 3, using writer sets and the dual ordering. We leave
that as future work.

### 2.3 Out of Scope

Following Lecture 4, this design does not prevent timing channels, termination
channels, memory-access side channels, or other covert channels. Volpano-style
non-interference is termination-insensitive: it protects the values written to
observable outputs, but it does not claim that runtime, termination behavior, or
resource usage is independent of secrets.

---

## 3. Label Model and Security Lattice

Author: Student B

We use the Myers-Liskov Decentralized Label Model (DLM) as the single label
model. This avoids mixing a fixed `Public/Friends/Private` lattice with DLM
labels. Mixing the two would force an extra consistency relation between two
different lattices, which is not given in the course papers and would therefore
weaken the proof.

### 3.1 DLM Confidentiality Labels

A confidentiality label is a partial map from owners to reader sets:

```
s : P -> PowerSet(P)
s = {o1: R1, ..., on: Rn}
```

The auxiliary functions are:

```
Owners(s) = Domain(s)
Readers(s, o) = s(o) if o in Owners(s), otherwise P
EffectiveReaders(s) = intersection over o in Owners(s) of Readers(s, o)
```

If `Owners(s)` is empty, the intersection is `P`, so the empty label is public.

Example:

```
s_record = {p: {p, H, d}, H: {H, d}}
```

A principal may read this record only if both the patient policy and the
hospital policy allow it. Thus the effective readers are:

```
EffectiveReaders(s_record) = {H, d}
```

### 3.2 Order, Join, and Meet

The DLM label set forms a lattice:

```
s1 <= s2 iff
  Owners(s1) subset Owners(s2), and
  for every o in Owners(s1): Readers(s1, o) superset Readers(s2, o)
```

Intuition: `s2` is at least as restrictive as `s1` if it has at least the same
owners and each existing owner allows no more readers.

Join:

```
Owners(s1 join s2) = Owners(s1) union Owners(s2)
Readers(s1 join s2, o) = Readers(s1, o) intersection Readers(s2, o)
```

Meet:

```
Owners(s1 meet s2) = Owners(s1) intersection Owners(s2)
Readers(s1 meet s2, o) = Readers(s1, o) union Readers(s2, o)
```

The bottom element is the empty label `{}`, which is readable by all principals.
The top element is a label where every principal is an owner and each owner
allows no readers.

### 3.3 Declassification

Declassification is allowed only by the DLM rule from Lecture 3:

An owner may relax only their own constraint. In this report, relaxation means
either adding readers to that owner's reader set or removing that owner from the
label. A program may perform such declassification only when the server has
recorded that the program acts for the relevant owner.

No command may relax another owner's constraint. This is the key reason DLM is
used instead of a simple fixed lattice: declassification needs owner authority.

---

## 4. Program Model and Static Checking

Author: Student B

### 4.1 White-Box Programs Only

Uploaded programs must be submitted as source code in a small imperative
language with explicit security labels on variables. The server parses and
type-checks the program before it is stored or executed.

We do not support arbitrary black-box programs. A black-box function can compute
anything from its inputs, so its output must conservatively receive at least the
join of all input labels. This is sound but too imprecise for the important
hospital use case: an anonymization program that reads patient records would
produce an output still labeled like the private records, so researchers could
not read the result unless a separate declassification mechanism was added.

We also do not support a hybrid white-box/black-box library model. It could be
made sound for a fixed certified library, but the three required papers do not
give a certification method for arbitrary black-box library functions. Keeping
only white-box programs gives a direct Volpano-style proof.

### 4.2 Static Type Checking

The server uses the Volpano type system from Lecture 2, with DLM labels in place
of `Low` and `High`. This is justified because the rules require a lattice
order, join, and meet, and DLM provides these.

Core syntax:

```
e ::= x | n | e op e
c ::= x := e
    | c ; c
    | if e then c else c
    | while e do c
    | return e
    | if_acts_for(prog, owner) { c }
    | x := declassify(e, s)
```

The core typing rules are the Volpano rules:

```
CONST:   gamma |- n : t
VAR:     gamma |- x : t      if gamma(x) <= t
ARITH:   gamma |- e1 op e2 : t if gamma |- e1:t and gamma |- e2:t
ASSIGN:  gamma |- x := e      only if label(e) <= gamma(x)
IF:      branches must type-check under a context at least as restrictive as
         the condition label
WHILE:   body must type-check under a context at least as restrictive as the
         loop condition label
```

These rules reject both explicit leaks and implicit leaks. For example, if `x`
has a private label and `y` is public, the command:

```
if x > 0 then y := 1 else y := 0
```

is rejected because the assignment to `y` occurs under a private control
context.

### 4.3 Why Static Instead of Runtime Monitoring

Lecture 4 explains why runtime monitoring is not enough. If an interpreter stops
when it detects an illegal assignment under a secret condition, the fact that it
stopped may itself reveal the secret condition. Therefore, programs are rejected
before execution. Rejection depends only on source code and labels, not on secret
runtime data.

---

## 5. Server API and Security Arguments

Author: Student C

All commands require an authenticated caller. Public identifiers such as file
IDs and program IDs have public labels. The server uses unified error messages
for missing and unauthorized data where file existence could itself be
confidential.

### 5.1 UPLOAD

```
UPLOAD(filename: string, data: bytes, label: DLMLabel) -> file_id or ERROR
```

Server behavior:

```
if Owners(label) is not empty and caller notin Owners(label):
    return ERROR
fid = fresh_id()
store file(fid, filename, data, label, uploader=caller)
return fid
```

Security argument: no data is released to another principal. The caller stores
data under a label they own, or under the public label. Since no read occurs, no
illegal flow is introduced.

### 5.2 READ

```
READ(file_id: int) -> bytes or ERROR
```

Server behavior:

```
f = internal_lookup(file_id)
if f is missing or caller notin EffectiveReaders(f.label):
    return ERROR_NOT_FOUND
return f.data
```

Security argument: data is returned exactly when the caller is an effective
reader. The unified error prevents unauthorized users from learning whether a
confidential file exists.

### 5.3 SHARE

```
SHARE(file_id: int, new_label: DLMLabel) -> OK or ERROR
```

Server behavior:

```
f = internal_lookup(file_id)
if f is missing or caller notin EffectiveReaders(f.label):
    return ERROR_NOT_FOUND
if caller notin Owners(f.label):
    return ERROR
if new_label changes any owner entry except caller's:
    return ERROR
if new_label introduces an owner not already in f.label:
    return ERROR
if caller's entry is not relaxed by adding readers or removing caller:
    return ERROR
f.label = new_label
return OK
```

Security argument: SHARE implements exactly the DLM declassification rule for
labels. The caller can relax only their own constraint. If the caller adds
readers to their entry, the effective reader set can only grow by the caller's
authorization. If the caller removes themselves as an owner, one term is removed
from the intersection defining `EffectiveReaders`, so the effective reader set
can only grow. Other owners' policies are unchanged.

### 5.4 UPLOAD_PROGRAM

```
UPLOAD_PROGRAM(name: string, source: string) -> program_id or ERROR
```

Server behavior:

```
(ast, gamma) = parse_with_label_annotations(source)
if parsing fails:
    return ERROR
if typecheck_DLM(ast, gamma) fails:
    return ERROR
required_authorities = extract_acts_for_and_declassify_sites(ast)
pid = fresh_id()
store program(pid, source, gamma, required_authorities, owner=caller)
return pid
```

Security argument: uploading and type-checking a program does not read user
data. A stored program has passed the DLM-instantiated Volpano type checker, so
for every principal `q`, terminating executions preserve `q`-equivalence. Thus
the program cannot leak private inputs into outputs whose labels allow
unauthorized readers.

### 5.5 DELEGATE

```
DELEGATE(program_id: int, owner: Principal) -> OK or ERROR
```

Server behavior:

```
if caller != owner:
    return ERROR
if program_id does not exist:
    return ERROR
store delegation(owner, program_id)
return OK
```

Security argument: no data moves. The command records that an owner consents to
the named program acting for them. This record is used only by EXECUTE when
checking declassification.

### 5.6 EXECUTE

```
EXECUTE(program_id: int, input_file_id: int, output_label: DLMLabel)
    -> output_file_id or ERROR
```

Server behavior:

```
prog = internal_lookup(program_id)
f = internal_lookup(input_file_id)
if prog is missing or f is missing:
    return ERROR_NOT_FOUND
if caller notin EffectiveReaders(f.label):
    return ERROR

s_in = f.label
s_out = output_label

relaxed_owners =
    owners removed from s_in in s_out
    union owners whose reader set is larger in s_out than in s_in

if relaxed_owners is empty:
    if not (s_in <= s_out):
        return ERROR
else:
    for each owner o in relaxed_owners:
        if no delegation(o, program_id):
            return ERROR
    if s_out introduces new owners not in s_in:
        return ERROR

result = sandbox_execute(prog, f.data)
fid = fresh_id()
store file(fid, result, s_out, uploader=caller)
return fid
```

Security argument: there are two cases.

First, if no declassification occurs, the server requires `s_in <= s_out`.
By the DLM ordering, this implies:

```
EffectiveReaders(s_out) subset EffectiveReaders(s_in)
```

So the output is readable only by principals who could already read the input.
The uploaded program has passed the Volpano type check, so it cannot create a
lower-labeled output through explicit or implicit flows.

Second, if the output label relaxes some owner's constraint, every relaxed owner
must have delegated authority to this program. Owners not relaxed remain at
least as restrictive as before. This implements explicit DLM declassification:
only an owner can authorize relaxing their own policy.

The sandbox is required for the proof. The program receives only its declared
input and returns only its declared output. It cannot read arbitrary server
storage, call the API, use the network, or communicate through shared memory.

### 5.7 LIST_READABLE_FILES

```
LIST_READABLE_FILES() -> list(file_id, filename)
```

Server behavior:

```
result = []
for each file f:
    if caller in EffectiveReaders(f.label):
        result.append((f.id, f.filename))
return result
```

Security argument: the command reveals file existence only for files the caller
is allowed to read. It reveals nothing about unauthorized files.

---

## 6. Declassification Example

Author: Student C

Suppose a hospital wants to publish the number of patients in a private record
set who match a condition, without publishing the underlying records.

Input label:

```
s_private = {p: {p, H, d}, H: {H, d}}
```

Output label:

```
s_stats = {H: {H, Stat, r}}
```

The anonymization program counts matching records and then explicitly
declassifies only the aggregate count:

```
count := 0;
while more_records do
    if diagnosis = target then count := count + 1 else count := count;
if_acts_for(anonymizer, H) {
    out := declassify(count, s_stats);
}
return out;
```

The declassification is allowed only if the hospital has delegated authority to
the anonymizer program. If patient-owned constraints are also relaxed, then the
relevant patient owner must also delegate authority; otherwise the command is
rejected. This prevents the hospital from silently removing a patient's policy.

The design intentionally declassifies the aggregate output, not the raw medical
records. This follows the DLM discipline that every declassification site is
explicit and tied to owner authority.

---

## 7. Design Choices and Rejected Alternatives

Author: Student B

### DLM instead of a fixed Low/High or Public/Friends/Private lattice

A fixed linear lattice is simple, but it cannot express several independent
owners. In the hospital scenario, each patient may have a separate policy, and
multiple owners may constrain the same record. DLM directly models this by
making labels maps from owners to reader sets. DLM is also required by the
assignment if we want declassification.

### One DLM lattice instead of mixing DLM with a product lattice

One draft used both DLM labels and a fixed product lattice. We do not keep that
choice. The course papers do not provide a rule for proving consistency between
those two unrelated label systems. A single DLM lattice is cleaner and gives a
direct lattice for Volpano's type rules.

### White-box programs instead of black-box programs

Black-box execution is sound only if the output label is at least the join of
all input labels. That is too imprecise for useful anonymization and gives no
non-interference proof for the program internals. White-box source programs let
the server use Volpano's type system and reject illegal explicit and implicit
flows before execution.

### Static checking instead of runtime monitoring

Runtime stopping leaks information when the stop occurs under a secret
condition, as discussed in Lecture 4. Static checking rejects unsafe programs
before secret data is involved.

### Confidentiality only instead of confidentiality plus integrity

Integrity is important for a real hospital system, but the assignment prioritizes
a precise proof over broad functionality. We therefore prove confidentiality
fully and state the integrity limitation explicitly. The future extension is
straightforward: add DLM integrity labels with writer sets and dual order, then
repeat the API proof for the integrity component.

### Explicit declassification instead of implicit sharing

Sharing by changing labels is not treated as ordinary assignment. It is an
explicit owner-authorized declassification step. This prevents a program or user
from accidentally weakening another owner's policy.

---

## 8. Overall Security Claim

Author: Student C

For any sequence of API commands by dishonest users and malicious uploaded
programs, no principal `q` learns information from data labeled `s` unless
`q in EffectiveReaders(s)`, except for explicit declassifications authorized by
the relevant owners.

The claim follows compositionally:

- UPLOAD stores data under an owner-approved label and releases no data.
- READ releases data only to effective readers.
- SHARE changes only the caller-owner's own DLM constraint.
- UPLOAD_PROGRAM stores only programs that pass the DLM-instantiated Volpano
  type checker.
- DELEGATE records owner consent and releases no data.
- EXECUTE either preserves the DLM order `s_in <= s_out` or requires explicit
  delegation for every relaxed owner.
- LIST_READABLE_FILES reveals only files already readable by the caller.

The main theorem used is Volpano non-interference, instantiated with the DLM
lattice. The DLM ordering gives the key link:

```
s_in <= s_out implies EffectiveReaders(s_out) subset EffectiveReaders(s_in)
```

Therefore an output readable by `q` can depend only on inputs already readable
by `q`, unless the relevant owner has explicitly authorized declassification.

---

# 中文版说明

下面这一部分是上面英文报告的中文说明版。英文部分更适合提交；中文部分主要
方便组内理解、检查和准备 presentation。

## 1. 系统里有哪些人

我们选的是作业里的医院场景。原因是医院场景最能体现信息流控制的重点：病人
数据有多个 owner，医生只能看被授权的数据，研究员只能看降密后的统计结果，
而且服务器还要执行不可信程序。

系统里的 principal 集合是：

```
P = {Srv, H} union Pt union Dr union Rs union {Stat}
```

含义如下：

- `Srv`：可信服务器。负责保存数据、检查 label、检查上传程序、运行沙箱。
- `H`：医院。可以拥有医院内部记录，也可以被病人授权。
- `p in Pt`：病人。每个病人控制自己病历相关的访问策略。
- `d in Dr`：医生。只有被 label 允许时才能读病人数据。
- `r in Rs`：研究员。只能看降密后的统计结果，不能看原始病历。
- `Stat`：统计服务，用来计算匿名统计结果。

我们不信任普通用户，也不信任上传的程序。用户可能乱调 API，程序可能故意
泄露数据。我们只信服务器的 label 检查、type checker、label store 和 sandbox。

## 2. 安全目标

主要目标是 confidentiality，也就是“谁能看什么”。

如果一个数据的 DLM label 是 `s`，那么 principal `q` 只有在下面条件成立时
才能知道这个数据的信息：

```
q in EffectiveReaders(s)
```

也就是说，只有所有 owner 都同意 `q` 读，`q` 才能读。

这个目标不仅限制直接读取，也限制程序里的间接泄露。例如：

```
if secret > 0 then public := 1 else public := 0
```

这里虽然没有直接把 `secret` 赋值给 `public`，但是 `public` 的值泄露了
`secret > 0`，所以这是 implicit flow，也必须被禁止。

我们没有把 integrity 做进主证明。原因是作业强调“少做但证明清楚”。如果做
integrity，每个文件和变量都要多一个 integrity label，每个 API proof 都要再
证明一遍。报告里保留了 future work：以后可以用 DLM 的 writer set 和对偶顺序
扩展 integrity。

我们也不处理 timing channel、termination channel 和其他 covert channel。
Lecture 4 里说过，Volpano 这种 non-interference 本身不是用来解决这些侧信道的。

## 3. 为什么用 DLM label

我们用 Myers-Liskov 的 DLM 作为唯一 label 模型。

一个 DLM confidentiality label 是 owner 到 reader set 的部分映射：

```
s = {o1: R1, ..., on: Rn}
```

意思是：

- `o1` 允许 `R1` 里的人读；
- `o2` 允许 `R2` 里的人读；
- 最后真正能读的人必须同时被所有 owner 允许。

所以：

```
EffectiveReaders(s) = 所有 owner 的 reader set 的交集
```

例子：

```
s_record = {p: {p, H, d}, H: {H, d}}
```

病人 `p` 允许 `{p, H, d}` 读，医院 `H` 允许 `{H, d}` 读。两边取交集后，
真正能读的是：

```
{H, d}
```

也就是说，病人自己虽然是 owner，但如果医院那一条 policy 没把病人列进去，
最终 effective readers 里就没有病人。这体现了 DLM 的“所有 owner 都要同意”。

## 4. DLM 的 lattice 怎么定义

DLM label 的顺序是：

```
s1 <= s2 iff
  Owners(s1) subset Owners(s2), and
  for every owner o in Owners(s1):
      Readers(s1, o) superset Readers(s2, o)
```

直觉是：`s2` 比 `s1` 更严格，因为它有更多 owner 约束，而且每个已有 owner
允许的人更少。

join 的意思是合并两个 label，并取更严格的限制：

```
Owners(s1 join s2) = Owners(s1) union Owners(s2)
Readers(s1 join s2, o) = Readers(s1, o) intersection Readers(s2, o)
```

bottom 是空 label `{}`，因为没有 owner 约束，所以所有人都能读，它就是 public。

top 是每个 principal 都是 owner，且每个 owner 都不允许任何人读。

## 5. 为什么只用白盒程序

我们要求用户上传 source code，并且每个变量都带 label。服务器先做静态
type checking，通过了才允许保存和执行。

不选黑盒程序的原因是：黑盒程序里面干了什么我们不知道。为了安全，黑盒输出
只能被标成所有输入 label 的 join。这样虽然安全，但太保守。例如匿名统计程序
读了病人病历以后，输出仍然会像原始病历一样严格，研究员还是不能看。这样
匿名统计这个场景就没意义了。

也不选“白盒调用黑盒库”的混合方案，因为课程三篇论文没有给我们一个认证任意
黑盒库函数的方法。为了证明简单，我们只保留白盒。

## 6. 为什么用静态检查，不用 runtime monitor

Lecture 4 说过，runtime monitor 有一个问题：如果程序运行到一半因为 illegal
flow 停止了，那么“它停了”这件事本身可能泄露 secret。

例如：

```
if secret > 0 then public := 1
```

如果 monitor 在 `secret > 0` 时停下，攻击者看到程序停了，就知道
`secret > 0`。所以不能等到运行时再发现问题，必须在执行前静态检查。

因此我们用 Volpano type system。程序上传后，服务器检查：

- private 数据不能赋值给 public 变量；
- private 条件控制下不能写 public 变量；
- declassify 必须显式写出来；
- declassify 必须有 owner 的 authority。

## 7. API 命令

### UPLOAD

上传文件：

```
UPLOAD(filename, data, label)
```

服务器检查：如果 label 有 owner，那么上传者必须是其中一个 owner。然后保存
数据和 label。

安全理由：这一步没有把数据发给别人，只是把数据按 owner 认可的 label 存起来。

### READ

读取文件：

```
READ(file_id)
```

服务器检查：

```
caller in EffectiveReaders(file.label)
```

只有通过这个检查才返回数据。

安全理由：读数据的人必须被所有 owner 允许。没权限时统一返回
`ERROR_NOT_FOUND`，这样攻击者连文件是否存在都不一定能知道。

### SHARE

修改 label，也就是分享或降密：

```
SHARE(file_id, new_label)
```

服务器检查：

- caller 必须是原 label 的 owner；
- caller 只能改自己的那一条 owner policy；
- 不能改别的 owner 的 reader set；
- 不能随便加新的 owner；
- 如果放宽权限，只能放宽 caller 自己的约束。

安全理由：这正是 DLM 的 declassification 规则。owner 只能 relax 自己的
constraint，不能替别人放权。

### UPLOAD_PROGRAM

上传程序：

```
UPLOAD_PROGRAM(name, source)
```

服务器会：

1. parse source code；
2. 读取变量 label；
3. 用 DLM 版本的 Volpano type system 检查；
4. 提取程序里需要的 `acts_for` / `declassify` 权限；
5. 通过后保存程序。

安全理由：程序还没运行，不会读取用户数据。通过检查的程序满足
non-interference，不会把 high/private 信息泄露到 low/public 输出。

### DELEGATE

owner 授权某个程序代表自己做 declassification：

```
DELEGATE(program_id, owner)
```

服务器检查：

```
caller == owner
```

安全理由：这一步不移动数据，只记录 owner 的同意。之后 EXECUTE 里如果程序
想放宽这个 owner 的约束，就必须查到这个 delegation。

### EXECUTE

执行程序：

```
EXECUTE(program_id, input_file_id, output_label)
```

服务器检查：

1. 程序存在；
2. 输入文件存在；
3. caller 能读输入文件；
4. 如果没有 declassification，那么必须有：

```
s_in <= s_out
```

这表示输出 label 至少和输入一样严格。

5. 如果 output_label 放宽了某些 owner 的约束，那么每个被放宽的 owner 都必须
   已经 delegate 给这个程序。

安全理由分两种情况：

- 没有 declassification：输出比输入更严格或一样严格，所以能读输出的人一定
  已经能读输入。
- 有 declassification：每个被放宽的 owner 都明确授权了，所以这是合法的显式
  降密。

程序必须在 sandbox 里运行。它只能读指定输入，只能返回指定输出，不能访问
服务器其他文件，不能调 API，不能联网。

### LIST_READABLE_FILES

列出 caller 能读的文件：

```
LIST_READABLE_FILES()
```

服务器只返回：

```
caller in EffectiveReaders(file.label)
```

的文件。

安全理由：它不会暴露未授权文件的存在。

## 8. Declassification 例子

医院想统计某种疾病的人数，然后把统计结果给研究员看。

原始病历 label：

```
s_private = {p: {p, H, d}, H: {H, d}}
```

统计结果 label：

```
s_stats = {H: {H, Stat, r}}
```

程序大概是：

```
count := 0;
while more_records do
    if diagnosis = target then count := count + 1 else count := count;
if_acts_for(anonymizer, H) {
    out := declassify(count, s_stats);
}
return out;
```

重点是：程序不是把原始病历 declassify，而是只 declassify 统计出来的 count。
而且只有当医院授权这个 anonymizer 程序 acting for `H` 时，才允许这样做。
如果病人的那条 owner constraint 也被放宽，那么病人也必须授权，否则服务器拒绝。

## 9. 我们为什么不选其他方案

### 不选固定 Low/High 或 Public/Friends/Private

固定等级太弱。医院场景里每个病人的隐私是独立的，不能把所有病人都塞进一个
`High`。而且 declassification 需要 owner，固定 lattice 没有 owner 概念。

### 不混合 DLM 和固定 product lattice

有一份草稿同时用了 DLM 和 `Public/Friends/Private/TopSecret`。这个会让系统
有两套 label。问题是课程论文没有告诉我们这两套 label 怎么保持一致，所以证明
会变复杂，也容易被老师质疑。

### 不选黑盒程序

黑盒程序安全但太粗。输出必须继承所有输入的最高机密性，导致匿名统计结果也
可能没人能读。白盒虽然麻烦，但能用 Volpano 的 non-interference theorem。

### 不选 runtime monitor

runtime monitor 停止执行本身会泄露信息。静态检查在运行前完成，不依赖 secret
runtime data，所以更适合这里。

### 不把 integrity 做进主设计

integrity 对真实医院系统很重要，但这份作业优先要求能证明清楚。我们选择先把
confidentiality 做完整。integrity 可以作为未来扩展：给每个文件和变量再加
writer set label，然后按对偶顺序检查。

## 10. 总安全结论

整体结论是：

不管用户多坏、上传程序多恶意，系统都不会让 principal `q` 知道 label `s` 的
数据，除非：

```
q in EffectiveReaders(s)
```

唯一例外是 owner 明确授权的 declassification。

核心证明链条是：

1. DLM label 是 lattice；
2. Volpano type system 可以用在任意 lattice 上；
3. 所以上传程序通过 DLM 版本 Volpano 检查后，满足 non-interference；
4. API 每一步都要么不移动数据，要么只给 effective readers，要么要求 owner
   明确授权 declassification；
5. 因此整个服务器不会产生非法信息流。
