# DTU 02244 Logic for Security
# Project on Information Flow — Secure Hosting Server Design

Group members: TODO: add names

Resources used: Denning and Denning (1977), Volpano, Smith and Irvine (1996),
Myers and Liskov (1997), the assignment text ifproject.pdf, and internal group
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

This is the Volpano non-interference theorem instantiated with DLM labels; the
instantiation is justified formally in Section 3.3.

### 2.2 Integrity

Integrity is discussed but not enforced in this design.

The assignment allows a design to focus only on confidentiality. We make that
choice because the most important grading priority is a small design that can be
proved precisely. Adding integrity would require a second DLM label on every
file and variable, dual type-checking rules for every command, and a second
proof argument for each API command. That extension is natural, but it doubles
the proof surface and makes it harder to keep the report within 15 pages.

Security consequence: this report does not prove that low-integrity input cannot
influence high-integrity output. A complete production system should add
integrity DLM labels using writer sets and the dual ordering (Myers and Liskov
1997). We leave that as future work.

### 2.3 Out of Scope

This design does not prevent timing channels, termination channels,
memory-access side channels, or other covert channels. Volpano-style
non-interference is termination-insensitive: it protects the values written to
observable outputs, but it does not claim that runtime, termination behavior, or
resource usage is independent of secrets. This limitation is stated explicitly
in Section 4.3.

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

### 3.2 The DLM Label Set is a Lattice

We define the ordering, join, and meet on DLM labels as follows:

**Ordering:**

```
s1 <= s2 iff
  Owners(s1) subset Owners(s2), and
  for every o in Owners(s1): Readers(s1, o) superset Readers(s2, o)
```

Intuition: `s2` is at least as restrictive as `s1` if it has at least the same
owners and each existing owner allows no more readers.

**Join (least upper bound):**

```
Owners(s1 join s2) = Owners(s1) union Owners(s2)
Readers(s1 join s2, o) = Readers(s1, o) intersection Readers(s2, o)
```

**Meet (greatest lower bound):**

```
Owners(s1 meet s2) = Owners(s1) intersection Owners(s2)
Readers(s1 meet s2, o) = Readers(s1, o) union Readers(s2, o)
```

We verify the lattice axioms:

- **Reflexivity:** `s <= s` holds since `Owners(s) subset Owners(s)` and
  `Readers(s, o) superset Readers(s, o)`.

- **Transitivity:** if `s1 <= s2 <= s3`, then `Owners(s1) subset Owners(s2)
  subset Owners(s3)`, and for every `o in Owners(s1)`:
  `Readers(s1, o) superset Readers(s2, o) superset Readers(s3, o)`.
  Therefore `s1 <= s3`.

- **`s1 join s2` is the least upper bound of `s1` and `s2`:** it contains all
  owners of both (so `s1 <= s1 join s2` and `s2 <= s1 join s2`), and takes the
  intersection of reader sets, which is the most restrictive combination
  consistent with both inputs.

- **`s1 meet s2` is the greatest lower bound:** it keeps only shared owners
  (so `s1 meet s2 <= s1` and `s1 meet s2 <= s2`), and takes the union of
  reader sets, which is the least restrictive combination dominated by both.

- **Bottom element:** the empty label `{}`. Since `Owners({}) = empty`, for
  every `s` we have `empty subset Owners(s)`, so `{} <= s`.
  `EffectiveReaders({}) = P`.

- **Top element:** the label `s_top = {(o: empty) | o in P}` where every
  principal is an owner and allows no readers. `EffectiveReaders(s_top) = empty`.

Therefore `(DLMLabels, <=, join, meet)` is a lattice.

### 3.3 Adapting Volpano Non-Interference to DLM

The Volpano non-interference theorem is originally stated for a two-element
lattice `{Low, High}`: if a program `c` passes the type check under environment
`gamma`, and two memories `mu1`, `mu2` agree on all Low variables, then
executing `c` on both yields memories `mu1'`, `mu2'` that also agree on all
Low variables.

To apply this to DLM, we re-interpret what "agree on all Low variables" means.
The adaptation proceeds in two steps.

**Step 1 — Lattice structure.** The Volpano typing rules (CONST, VAR, ARITH,
ASSIGN, IF, WHILE, COMPOSE) use the ordering `<=` only to check that information
does not flow upward. The proof of non-interference proceeds by structural
induction on the program, and at each step uses only: (a) that `<=` is a partial
order, (b) that join exists (used in IF/WHILE to raise the context label), and
(c) the ASSIGN rule's side condition. Since DLMLabels is a lattice (Section 3.2),
all three conditions hold. The type rules are therefore applicable to any
lattice-ordered set of labels, including DLM labels.

**Step 2 — Semantic adaptation.** We fix a principal `q` and define:

Two memories `mu1`, `mu2` are **q-equivalent** (written `mu1 ~q mu2`) iff for
every variable `x` with `gamma(x) = s`: if `q in EffectiveReaders(s)` then
`mu1(x) = mu2(x)`.

This replaces Low-equivalence with q-equivalence. The non-interference theorem
then becomes: if `gamma |- c : tau`, and `mu1 ~q mu2`, and both executions
terminate, then the resulting memories are also q-equivalent.

The structural-induction proof carries through because it does not depend on
the cardinality of the label set. The key case is the ASSIGN rule, which
requires `tau' <= tau` where `tau' = gamma(x)` is the target variable's label
and `tau` is the source expression's label. We must show that no principal
learns anything new from the assignment. Since `tau' <= tau`, by the DLM
ordering definition: `Owners(tau') superset Owners(tau)`, and
`Readers(tau', o) subset Readers(tau, o)` for every `o in Owners(tau)`.
Therefore:

```
EffectiveReaders(tau') = intersect_{o in Owners(tau')} Readers(tau', o)
                       ⊆ intersect_{o in Owners(tau)}  Readers(tau', o)
                       ⊆ intersect_{o in Owners(tau)}  Readers(tau, o)
                       = EffectiveReaders(tau)
```

So `tau' <= tau` implies `EffectiveReaders(tau') subset EffectiveReaders(tau)`:
the target variable `x` has fewer effective readers than the source expression.
Any principal `q` who can read `x` can also read the source expression, so the
assignment reveals nothing new. The IF/WHILE rules raise the context label to
the join with the condition label, ensuring implicit flows through control flow
are also accounted for.

We therefore state: **any program that passes the DLM-instantiated Volpano type
check satisfies q-non-interference for every principal `q`.** This is the
guarantee invoked in the security arguments for UPLOAD_PROGRAM and EXECUTE.

### 3.4 Declassification Rule

An owner may relax only their own constraint. Relaxation means either adding
readers to that owner's reader set or removing that owner from the label. A
program may perform such declassification only when the server has recorded that
the program acts for the relevant owner via DELEGATE.

No command may relax another owner's constraint. This is the key reason DLM is
used: declassification is tied to owner authority, not to a global security
level.

---

## 4. Program Model and Static Checking

Author: Student B

### 4.1 White-Box Programs Only

Uploaded programs must be submitted as source code in a small imperative
language with explicit security labels on variables. The server parses and
type-checks the program before it is stored or executed.

We do not support arbitrary black-box programs. A black-box function can compute
anything from its inputs, so its output must conservatively receive at least the
join of all input labels. This is sound but too imprecise for the hospital use
case: an anonymization program that reads patient records would produce an output
still labeled like the private records, so researchers could not read the result
unless a separate declassification mechanism was added.

We also do not support a hybrid white-box/black-box library model. It could be
made sound for a fixed certified library, but the three required papers do not
give a certification method for arbitrary black-box library functions. Keeping
only white-box programs gives a direct proof via the result in Section 3.3.

### 4.2 Static Type Checking

The server applies the Volpano typing rules with DLM labels in place of `Low`
and `High`. This substitution is justified by Section 3.3: the rules require
only a lattice order and join, both of which DLM provides.

Core syntax:

We define the core imperative language for uploaded programs, with extensions for DLM-authorized declassification strictly aligned with Myers and Liskov (1997):

```
e ::= x | n | e op e
c ::= x := e
    | c ; c
    | if e then c1 else c2
    | while e do c
    | return e
    | if_acts_for(prog, o) { c }
    | x := declassify(e, s_new)
```
Where：
- `x` is a variable with a static DLM label declared in the type environment `gamma` ；
- `prog` is the program identifier (fixed at upload time for the current program);
- `o` is a principal (owner);
- `s_new` is a valid DLM label.

The typing rules are:

We use a standard Volpano-style typing judgment:
- `gamma |- e : s`: expression `e` has security label `s` under type environment `gamma`;
- `gamma, pc |- c` command `c` is well-typed under type environment `gamma` and program counter label `pc` (the label of the control flow context, used to prevent implicit flows).

```
CONST:   gamma |- n : bottom     (bottom = {}, the public label)
VAR:     gamma |- x : gamma(x)     
ARITH:   gamma |- e1 op e2 : s1 join s2, where gamma |- e1 : s1, gamma |- e2 : s2
ASSIGN:  gamma, pc |- x := e
         iff gamma |- e : s_e, and (pc join s_e) <= gamma(x)
COMPOSE: gamma, pc |- c1 ; c2
         iff gamma, pc |- c1 and gamma, pc |- c2
IF:      gamma, pc |- if e then c1 else c2
         iff gamma |- e : s_e, and gamma, (pc join s_e) |- c1, and gamma, (pc join s_e) |- c2
WHILE:   gamma, pc |- while e do c
         iff gamma |- e : s_e, and gamma, (pc join s_e) |- c
RETURN:  gamma, pc |- return e
         iff gamma |- e : s_e, and pc <= s_e

IF_ACTS_FOR: gamma, pc |- if_acts_for(prog, o) { c }
             iff:
             1. The program `prog` is the current uploaded program (statically fixed at upload time);
             2. `o` is a valid principal in the system;
             3. gamma, pc |- c (the block body is well-typed under the current context)
             This rule statically marks that the enclosed code requires a valid delegation from owner `o` to `prog` at runtime, enforced by the EXECUTE API.

DECLASSIFY: gamma, pc |- x := declassify(e, s_new)
            iff:
            1. gamma |- e : s_old;
            2. s_new is a valid relaxation of s_old:
               a. Owners(s_new) subset Owners(s_old) (no new owners may be added);
               b. For all o in Owners(s_new): Readers(s_new, o) superset Readers(s_old, o) (only reader set expansion is allowed for retained owners);
            3. The declassification is enclosed in an `if_acts_for(prog, o)` block for every owner o in the relaxed set (owners removed from s_old, or with expanded reader sets in s_new);
            4. (pc join s_new) <= gamma(x)
            This rule enforces that declassification is only performed when explicitly authorized by all affected owners, strictly following the DLM decentralized declassification model.
```

These rules reject both explicit and implicit leaks. For example, if `x` has a
private label and `y` is public, the command:

```
if x > 0 then y := 1 else y := 0
```

is rejected because the assignment to `y` occurs under a control context `pc join s_x` (where `s_x` is private), and `private <= public` is false, violating the ASSIGN rule's side condition.

### 4.3 Why Static Instead of Runtime Monitoring

If a runtime monitor stops execution when it detects an illegal assignment under
a secret condition, the fact that execution stopped may itself reveal the secret
condition. For example:

```
if secret > 0 then public := 1
```

If the monitor stops here when `secret > 0`, an observer who sees the stop
learns that `secret > 0`. Static checking avoids this entirely: programs are
rejected before any secret data is involved. Rejection depends only on source
code and label annotations, not on runtime values.

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

Security argument: data is returned exactly when `caller in
EffectiveReaders(f.label)`, i.e., when every owner of `f.label` has included
the caller in their reader set. The unified error message ("Not found" for both
missing and unauthorized) prevents callers from learning whether a confidential
file exists under a given ID.

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
f.label = new_label
return OK
```

Security argument: the server enforces the DLM declassification rule — the
caller may only change their own entry. Two cases arise:

**Case 1: caller adds readers to their own entry.** Formally, `s'` differs from
`s` only in `Readers(s', caller) superset Readers(s, caller)`. Then:

```
EffectiveReaders(s') = intersect_{o in Owners(s')} Readers(s', o)
                     = Readers(s', caller) intersect (intersect_{o != caller} Readers(s, o))
                    ⊇ Readers(s, caller)  intersect (intersect_{o != caller} Readers(s, o))
                     = EffectiveReaders(s)
```

So `EffectiveReaders(s') superset EffectiveReaders(s)`: the effective reader set
can only grow. No existing reader loses access.

**Case 2: caller removes themselves from Owners.** Then
`Owners(s') = Owners(s) \ {caller}`. Let
`A = EffectiveReaders(s)` and `B = EffectiveReaders(s')`:

```
A = intersect_{o in Owners(s)}          Readers(s, o)
B = intersect_{o in Owners(s)\{caller}} Readers(s, o)
```

Since `A = B intersect Readers(s, caller)`, we have `A subset B`, so
`EffectiveReaders(s') superset EffectiveReaders(s)`. Removing an owner from the
intersection can only increase the effective reader set.

In both cases, other owners' constraints are unchanged, and the DLM rule is
satisfied.

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
s_input_declared = gamma(input_var)
s_output_declared = label of the returned expression (verified during type check)
pid = fresh_id()
store program(pid, source, gamma, s_input_declared, s_output_declared, required_authorities, owner=caller)
return pid
```

Security argument: uploading and type-checking a program does not read user
data. A stored program has passed the DLM-instantiated Volpano type checker, so
by the result of Section 3.3, for every principal `q`, terminating executions
preserve `q`-equivalence. The program cannot leak private inputs into outputs
whose labels allow unauthorized readers, through either explicit assignments or
implicit control-flow dependencies.

**Model boundary:** the non-interference guarantee applies to the observable
output of terminating executions. It does not cover information leaked via
timing side channels or memory-access patterns. This is a known limitation of
the Volpano model, stated as out of scope in Section 2.3.

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
the named program acting for them. The check `caller = owner` ensures a user
cannot grant another user's authority. This record is used only by EXECUTE when
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

if not (s_in <= prog.s_input_declared):
    return ERROR
if not (prog.s_output_declared <= s_out):
    return ERROR
relaxed_owners =
    { o in Owners(s_in) | o notin Owners(s_out) }           // dropped owners
    union
    { o in Owners(s_in) intersect Owners(s_out) |
      Readers(s_out, o) strict superset Readers(s_in, o) }  // relaxed reader sets

if relaxed_owners is empty:
    if not (s_in <= s_out):
        return ERROR
else:
    for each owner o in relaxed_owners:
        if no delegation(o, program_id):
            return ERROR
    if Owners(s_out) \ Owners(s_in) != empty:
        return ERROR

result = sandbox_execute(prog, f.data)
fid = fresh_id()
store file(fid, f"output_{prog.name}_{f.filename}", result, s_out, uploader=caller)
return fid
```

Security argument: we verify four sequential, mutually reinforcing conditions to ensure no illegal information flow.

**Check 0 — Static Label Compatibility.** We enforce
`s_in <= prog.s_input_declared` and `prog.s_output_declared <= s_out`.
- The first check ensures the input file's label is no more restrictive than the program's statically declared input label. By the DLM lattice ordering, this means `EffectiveReaders(s_in) superset EffectiveReaders(prog.s_input_declared)`: all principals authorized to read the program's input are already authorized to read the input file. This ensures the program's type check, which was performed against `prog.s_input_declared`, is fully valid for the actual input data — no unaccounted-for restrictions are introduced at runtime.
- The second check ensures the program's statically type-checked output label is no more restrictive than the requested output file label. By the DLM ordering, this means `EffectiveReaders(prog.s_output_declared) superset EffectiveReaders(s_out)`: all principals authorized to read the output file are already authorized to read the program's output. This ensures the program's type-enforced non-interference guarantee is not violated by the output file's label policy.

**Check 1 — Caller authorization.** The caller must be in
`EffectiveReaders(f.label)`, ensuring they are authorized to supply this input.

**Check 2a — No-declassification path.** When `relaxed_owners` is empty, we
require `s_in <= s_out`. By the DLM ordering, this means
`Owners(s_in) subset Owners(s_out)` and `Readers(s_out, o) subset Readers(s_in, o)`
for every `o in Owners(s_in)`. Therefore:

```
EffectiveReaders(s_out) = intersect_{o in Owners(s_out)} Readers(s_out, o)
                        ⊆ intersect_{o in Owners(s_in)}  Readers(s_out, o)
                        ⊆ intersect_{o in Owners(s_in)}  Readers(s_in, o)
                        = EffectiveReaders(s_in)
```

So the output is readable only by principals already authorized to read the
input. The program passed the type check, so by Section 3.3 it cannot write
to a variable whose effective readers are a strict superset of the source
variable's effective readers. No unauthorized principal can reach the output.

**Check 2b — Declassification path.** For each owner `o in relaxed_owners`,
a registered delegation is required. The check
`Owners(s_out) \ Owners(s_in) != empty` guards against introducing new owners
in the output label, which would tighten rather than relax the label and is
therefore rejected. Every relaxation requires the relevant owner's explicit
consent. Owners not in `relaxed_owners` retain their full constraints.

**Sandbox guarantee.** The Volpano type analysis reasons about information flow
between the program's labeled variables. For this to be meaningful, the program
must receive input exclusively through its declared input variable and produce
output exclusively through its return value — it must not access server storage,
call API commands, use the network, or share memory with the server.
`sandbox_execute` enforces exactly this: the program runs in an isolated process
whose only interface to the outside world is the single input value and the
single returned output value. Under this isolation, the program's labeled
variables constitute the complete information universe the type analysis covers,
and the non-interference guarantee of Section 3.3 applies without gaps.

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
is authorized to read. No information about unauthorized files is revealed.
This is consistent with READ's unified error: both commands reveal the existence
of a file if and only if `caller in EffectiveReaders(f.label)`.

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

The `s_private` label requires consent from both the patient `p` and the
hospital `H`. The `s_stats` label removes `p` as an owner and expands `H`'s
reader set to include `Stat` and `r`. Both changes relax the original label, so
EXECUTE will require a delegation from every affected owner.

The anonymization program counts matching records and declassifies only the
aggregate count:

```
input_var : label_of(input_var) = s_private;
count : label_of(count) = s_private;
out   : label_of(out)   = s_stats;

count := 0;
while more_records do
    if diagnosis = target then count := count + 1 else count := count;
if_acts_for(anonymizer, H) {
    if_acts_for(anonymizer, p) {
        out := declassify(count, s_stats);
    }
}
return out;
```

The declassification is permitted only if the hospital has called
`DELEGATE(anonymizer_id, H)` and the patient has called `DELEGATE(anonymizer_id, p)`. Because `p` is dropped from `Owners`, the patient
constraint is also relaxed, so the relevant patient must also have delegated
authority to the program; otherwise EXECUTE returns an error. This prevents the
hospital from silently overriding a patient's policy.

The type checker verifies that `count` is computed only from inputs labeled
`s_private` or less, and that `out` is written only inside an `if_acts_for`
block that confirms the required delegation at runtime. The declassification is
therefore both statically checked and owner-authorized.

---

## 7. Design Choices and Rejected Alternatives

Author: Student B

### DLM instead of a fixed Low/High or Public/Friends/Private lattice

A fixed linear lattice is simple, but it cannot express several independent
owners. In the hospital scenario, each patient may have a separate policy, and
multiple owners may constrain the same record. DLM directly models this by
making labels maps from owners to reader sets. DLM is also necessary for
explicit declassification: without an owner concept, there is no principled way
to authorize relaxation of a constraint.

### One DLM lattice instead of mixing DLM with a product lattice

One draft used both DLM labels and a fixed product lattice. We do not keep that
choice. The course papers do not provide a rule for proving consistency between
those two unrelated label systems. A single DLM lattice is cleaner and gives a
direct lattice for the Volpano type rules.

### White-box programs instead of black-box programs

Black-box execution is sound only if the output label is at least the join of
all input labels. That is too imprecise for useful anonymization and gives no
non-interference proof for the program internals. White-box source programs let
the server apply the Volpano type system and reject illegal explicit and implicit
flows before execution.

### Static checking instead of runtime monitoring

If a runtime monitor stops execution when it detects an illegal flow under a
secret condition, the stop itself reveals information about the secret. Static
checking rejects unsafe programs before any secret data is involved, so no such
leak can occur. This aligns with the certification framework for secure information flow defined in Denning and Denning (1977), which requires pre-execution validation of program flow safety.

### Confidentiality only instead of confidentiality plus integrity

Integrity is important for a real hospital system, but the assignment prioritizes
a precise proof over broad functionality. We prove confidentiality fully and
state the integrity limitation explicitly. The future extension is
straightforward: add DLM integrity labels with writer sets and the dual order,
then repeat the API proof for the integrity component.

### Explicit declassification instead of implicit sharing

Sharing by changing labels is not treated as ordinary assignment. It is an
explicit owner-authorized declassification step, enforced by both the SHARE
command and the DELEGATE + EXECUTE mechanism. This prevents a program or user
from accidentally or maliciously weakening another owner's policy.

---

## 8. Overall Security Claim

Author: Student C

For any sequence of API commands by dishonest users and malicious uploaded
programs, no principal `q` learns information from data labeled `s` unless
`q in EffectiveReaders(s)`, except for explicit declassifications authorized by
the relevant owners.

The claim follows compositionally:

- UPLOAD stores data under an owner-approved label and releases no data.
- READ releases data only to effective readers; the unified error prevents
  existence probing.
- SHARE changes only the caller-owner's own DLM constraint, proven in Section
  5.3 to only increase `EffectiveReaders`.
- UPLOAD_PROGRAM stores only programs that pass the DLM-instantiated Volpano
  type checker; by Section 3.3 these satisfy q-non-interference for every `q`.
- DELEGATE records owner consent and releases no data.
- EXECUTE either preserves `s_in <= s_out` (proven in Section 5.6 to imply
  `EffectiveReaders(s_out) subset EffectiveReaders(s_in)`) or requires explicit
  delegation for every relaxed owner.
- LIST_READABLE_FILES reveals only files already readable by the caller.

The foundational guarantee rests on Section 3.3: the DLM label set is a lattice
(Section 3.2), the Volpano type rules apply to any lattice, and the
non-interference proof carries through with the DLM-adapted definition of
q-equivalence. This closes the gap between the original Volpano theorem and its
application in this design.
