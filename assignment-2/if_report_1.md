# 02244 Logic for Security
## Project: Information Flow — Secure Hosting Server Design

---

# 1. Participants and Roles

*[Author: Student A]*

The system involves the following principals (constituting the set P of all principals):

- **Server (S):** The trusted hosting server. The server is the only fully trusted component. It enforces all security policies, performs information flow analysis on uploaded programs, and executes all API commands.
- **Users (U1, U2, ...):** Registered human users who upload, label, share, and access data. Each user is identified by a unique, authenticated username. Users are not fully trusted — they may be dishonest or attempt to exceed their authorization within the bounds of the API.
- **Programs (Prog1, Prog2, ...):** User-written programs submitted in source code form. Programs are untrusted by default; they may contain bugs or deliberately malicious logic. They are not principals in the ownership sense but may be granted delegated authority by a user owner (see Section 4.3 and DELEGATE command).

For the hospital scenario used throughout this report, the principals are P = {Server, Hospital, Doctor, Patient, Researcher}. The Hospital owns medical records; Doctors are authorized readers; Patients are data subjects who may grant additional permissions; Researchers may access only properly declassified data.

---

# 2. Security Goals

*[Author: Student A]*

## 2.1 Confidentiality

The primary security goal is confidentiality: no information shall flow from a data item with label s to a principal q unless q is an effective reader of s according to the DLM policy, i.e., q ∈ EffectiveReaders(s). This must hold regardless of the behavior of other users or uploaded programs.

We formalize this as a Non-Interference property (adapted from Volpano et al. 1996 to the DLM setting, see Section 3.3): for any principal q and any two server states that agree on all data visible to q (i.e., all files whose label s satisfies q ∈ EffectiveReaders(s)), any sequence of API commands produces outputs that are indistinguishable to q.

## 2.2 Integrity (Out of Scope)

Integrity — preventing untrusted data from influencing trusted data — is not addressed in this design. This is a deliberate and principled choice. The DLM framework supports integrity labels (replacing Readers with Writers, with the dual ordering, as shown in lecture3.pdf), but incorporating both dimensions would require: (a) dual-label annotations on every file and program variable, (b) dual type-checking of every uploaded program, and (c) dual security arguments for every API command. Given the 15-page limit and the assignment's explicit advice to "do fewer things 100% right rather than everything partially", we restrict to confidentiality.

The security consequence of omitting integrity is that a malicious uploaded program could, in principle, overwrite trusted data with untrusted computed values — provided the caller has write access via the API. We accept this limitation. A complete system would add integrity labels and a dual type-check; we note where such extensions would fit naturally in the design.

## 2.3 Threat Model

We assume the server is correct and trusted. TLS with user authentication is in place (given by the assignment). Users may be dishonest: they may call any API command with any arguments permitted by the interface. Uploaded programs may be malicious: they may attempt to leak data through explicit assignments, implicit control-flow dependencies, or any combination thereof that is expressible in the source language. We do not consider side channels (timing, memory footprint); this is a known limitation of the Volpano Non-Interference model, which we discuss explicitly in Section 5.4.

---

# 3. Security Lattice and Label Structure

*[Author: Student B]*

We adopt the Myers-Liskov Decentralized Label Model (DLM) exclusively. Labels are not fixed globally; each data item carries a DLM confidentiality label chosen (within constraints) by the uploading user. We explain in this section why the DLM label set forms a lattice, which is the structural prerequisite for applying the Volpano type system (see Section 3.3).

## 3.1 DLM Confidentiality Labels

A DLM confidentiality label is a partial function s : P → PowerSet(P). We write it as a set of pairs {(o1: R1), (o2: R2), ...} where each o_i is an owner and R_i is the set of readers that o_i permits. Formally:

```
Owners(s)     = Domain(s)
Readers(s, o) = s(o)  if o ∈ Owners(s)
              = P     otherwise  (no constraint from o)
EffectiveReaders(s) = ⋂_{o ∈ Owners(s)} Readers(s, o)
                    = P  if Owners(s) = ∅  (bottom element, label: ⊥)
```

**Example (hospital):** s_priv = {(Hospital: {Hospital, Doctor})} has EffectiveReaders = {Hospital, Doctor}. The public label ⊥ (no owners) has EffectiveReaders = P.

## 3.2 The DLM Label Set is a Lattice

We define the ordering, join, and meet on DLM labels as follows (from lecture3.pdf):

**Ordering:**
```
s1 ⊑ s2  iff  Owners(s1) ⊆ Owners(s2)
         and  Readers(s1, o) ⊇ Readers(s2, o)  for every o ∈ Owners(s1)
```

Intuitively, s2 is at least as restrictive as s1: it has more owners (more constraints) and each existing owner allows fewer readers.

**Join (least upper bound):**
```
Owners(s1 ⊔ s2)     = Owners(s1) ∪ Owners(s2)
Readers(s1 ⊔ s2, o) = Readers(s1,o) ∩ Readers(s2,o)
```

**Meet (greatest lower bound):**
```
Owners(s1 ⊓ s2)     = Owners(s1) ∩ Owners(s2)
Readers(s1 ⊓ s2, o) = Readers(s1,o) ∪ Readers(s2,o)
```

We claim (following lecture3.pdf) that (DLMLabels, ⊑, ⊔, ⊓) is a lattice. The key properties are:

- **Reflexivity:** s ⊑ s holds since Owners(s) ⊆ Owners(s) and Readers(s,o) ⊇ Readers(s,o).
- **Transitivity:** if s1 ⊑ s2 ⊑ s3, then Owners(s1) ⊆ Owners(s2) ⊆ Owners(s3) and for o ∈ Owners(s1): Readers(s1,o) ⊇ Readers(s2,o) ⊇ Readers(s3,o), so s1 ⊑ s3.
- **s1 ⊔ s2** is the least label that is ⊒ both s1 and s2: it contains all owners of both and takes the intersection of their reader sets (most restrictive consistent combination).
- **s1 ⊓ s2** is the greatest label ⊑ both: it keeps only shared owners and takes the union of reader sets.
- **Bottom element:** ⊥ (empty map). Owners = ∅, so every principal is an effective reader. For every s, ⊥ ⊑ s trivially (Owners(⊥) = ∅ ⊆ Owners(s)).
- **Top element:** the label s_top = {(o: ∅) | o ∈ P} in which every principal is an owner and allows no readers. EffectiveReaders(s_top) = ∅.

Thus DLMLabels is a lattice with bottom ⊥ and top s_top.

## 3.3 Adapting Volpano Non-Interference to DLM

The Volpano Non-Interference theorem (lecture2.pdf) is originally stated for a two-element lattice {Low, High}. The statement is: if a program c passes the type check under environment γ, and two memories μ1, μ2 agree on all Low variables, then executing c on both yields memories μ1', μ2' that also agree on all Low variables.

To apply this to DLM, we must re-interpret what "agree on all Low variables" means. The adaptation proceeds in two steps:

**Step 1 — Lattice structure.** The Volpano type-checking rules (CONST, VAR, ARITH, ASSIGN, IF, WHILE, COMPOSE) use the ordering ⊑ only to check that information does not flow upward. The proof of Non-Interference proceeds by structural induction on the program, and at each step uses only: (a) that ⊑ is a partial order, (b) that join exists (used in IF/WHILE to raise the context label), and (c) the ASSIGN rule's check γ(x) = τ and τ' ⊑ τ. Since DLMLabels is a lattice (Section 3.2), all three conditions hold. The type rules are therefore sound for any lattice-ordered set of labels, including DLM labels.

**Step 2 — Semantic adaptation.** In the DLM setting, we fix a principal q and define the Non-Interference statement relative to q as follows:

```
Two memories μ1, μ2 are q-equivalent (written μ1 ~q μ2) iff
  for every variable x with γ(x) = s:
    if q ∈ EffectiveReaders(s) then μ1(x) = μ2(x)
```

This replaces the Low-equivalence of Volpano with q-equivalence. With this definition, the Non-Interference theorem becomes: if γ ⊢ c : τ, and μ1 ~q μ2, and both executions terminate (μ1 ⊢ c ⇒ μ1', μ2 ⊢ c ⇒ μ2'), then μ1' ~q μ2'.

The proof carries through unchanged because the structural-induction argument does not depend on the cardinality of the label set; it depends only on the lattice properties (Step 1) and on the q-equivalence relation being preserved by each typing rule. The key case is the ASSIGN rule: it requires τ' ⊑ τ, where τ' = γ(x) is the target variable's label and τ is the source expression's label. Since τ' ⊑ τ, by the DLM ordering: Owners(τ') ⊇ Owners(τ), and Readers(τ', o) ⊆ Readers(τ, o) for every o ∈ Owners(τ). Therefore:

```
EffectiveReaders(τ') = ⋂_{o ∈ Owners(τ')} Readers(τ', o)
                     ⊆ ⋂_{o ∈ Owners(τ)}  Readers(τ', o)   [Owners(τ) ⊆ Owners(τ')]
                     ⊆ ⋂_{o ∈ Owners(τ)}  Readers(τ, o)    [Readers(τ',o) ⊆ Readers(τ,o)]
                     = EffectiveReaders(τ)
```

So τ' ⊑ τ implies EffectiveReaders(τ') ⊆ EffectiveReaders(τ): the target variable x has fewer effective readers than the source expression. Any principal q who can read x (q ∈ EffectiveReaders(τ')) can also read the source expression (q ∈ EffectiveReaders(τ)). The assignment therefore reveals nothing to a principal who could not already observe the source value — q-equivalence of memories is preserved. The IF/WHILE rules use the join to raise the context label, ensuring implicit flows through condition variables are treated as carrying the join of the context and the condition's label.

We therefore state: **any program that passes the DLM-instantiated Volpano type check satisfies q-Non-Interference for every principal q.** This is the guarantee we invoke in the security arguments for UPLOAD_PROGRAM and EXECUTE.

---

# 4. Design Choices and Reasoning

*[Author: Student B]*

## 4.1 Choice of Information Flow Method

The assignment permits use of Denning (1977), Volpano et al. (1996), and Myers-Liskov (1997). We use all three as a foundation but build the design around Volpano and Myers-Liskov for the following reasons:

Denning (1977) introduced the lattice-based certification of programs for secure information flow and defines the core flow rules we rely on conceptually. However, Denning's method is based on data-flow graph analysis for a specific program model and does not provide a structural induction proof for general imperative languages with dynamic control flow. For our purpose — verifying user-uploaded source programs — we need a method with a formal soundness theorem applicable to the full command language.

Volpano et al. (1996) provide exactly this: a type system for an imperative command language with a constructive Non-Interference proof by structural induction. This is the method we use for program verification. Its key advantage is that the proof works for any lattice of labels (as shown in Section 3.3), making it directly applicable to DLM labels.

Myers-Liskov (1997) provide the DLM label structure, which is necessary for a multi-user system where each user independently controls their own data. A single global lattice (as in Denning/Volpano's original presentation) would require a central authority to define all security classes, which is inappropriate for a hosting service with many independent users.

## 4.2 White-box Programs

Programs must be submitted as annotated source code (each variable carries a DLM label). The server performs a static type check before storing the program. This is the only approach that gives us a formal Non-Interference guarantee (Section 3.3). Black-box programs would require treating all output as carrying the join of all input labels — a severe over-approximation that would make programs nearly unusable. A combination (white-box programs calling fixed black-box library functions) could be supported by assigning conservative fixed labels to library outputs; we leave this as future work.

## 4.3 Declassification

We support declassification via the DLM rule: an owner o may relax only their own constraint (add readers to their entry, or remove themselves as an owner). Operationally, this is expressed through the DELEGATE command: owner o explicitly grants a program the right to act on behalf of o, which enables that program to use declassify() on o's constraint. No program may declassify without a registered delegation.

## 4.4 No Integrity

As argued in Section 2.2, integrity is out of scope. The design accommodates a future integrity extension: each file would carry a second label (an integrity label), programs would have dual variable annotations, and EXECUTE would additionally require that the output integrity label is ⊑ the input integrity label (data can only flow from more trusted to less trusted in the integrity dimension).

---

# 5. Server API

*[Author: Student C]*

We describe eight commands. Each section gives: parameters with types and labels, server behavior as pseudocode, and a security argument showing no illegal information flow occurs. The notation s = {(o: R, ...)} denotes a DLM label; ⊥ denotes the public (no-owner) label.

**Convention:** "caller" denotes the authenticated user. File IDs and program IDs are public integers (label ⊥).

---

## 5.1 UPLOAD(filename: string{⊥}, data: bytes{s}, label: DLMLabel) → file_id

**Parameters:**
- `filename: string{⊥}` — a public name for the file.
- `data: bytes` — the content to store, to be labeled s.
- `label s: DLMLabel` — chosen by caller; caller must satisfy caller ∈ Owners(s) or Owners(s) = ∅.

**Server Behavior:**
```
UPLOAD(caller, filename, data, s):
  if Owners(s) ≠ ∅ and caller ∉ Owners(s):
    return ERROR("Caller must be an owner of the chosen label")
  fid = fresh_id()
  store file(id=fid, filename=filename, data=data, label=s, uploader=caller)
  return OK(fid)
```

**Security Argument:** No data is sent to any output channel. The only flow is from the caller's input into server storage, under label s. Since the caller is authenticated and is required to be an owner of s (or s is public), no one else's label policy is being imposed without consent. No confidential information flows to any principal at this step.

---

## 5.2 READ(file_id: int{⊥}) → bytes{s}

**Parameters:**
- `file_id: int{⊥}` — identifier of the file to read.

**Server Behavior:**
```
READ(caller, file_id):
  f = internal_lookup(file_id)   // server-internal, not exposed to caller
  if f = NOT_FOUND or caller ∉ EffectiveReaders(f.label):
    return ERROR("Not found")    // unified error: prevents existence probing
  return OK(f.data)
```

**Security Argument:** The server returns data only when caller ∈ EffectiveReaders(f.label), which by definition holds iff every owner o in f.label has included caller in Readers(f.label, o). This is precisely the DLM authorization condition for reading.

The unified error message ("Not found" for both missing files and unauthorized access) prevents a caller from probing whether a file with a given ID exists. This matters because file existence itself may be confidential: knowing that a patient has a medical record is sensitive information. A caller learns only that they cannot access the file, not whether it exists. The file_id is public, but the existence of the file under that ID is not — the unified error preserves this. Note that LIST_MY_FILES (Section 5.7) reveals the existence of files to which the caller already has access; this is consistent since both commands reveal existence if and only if caller ∈ EffectiveReaders.

---

## 5.3 SHARE(file_id: int{⊥}, new_label: DLMLabel) → OK

**Parameters:**
- `file_id: int{⊥}` — the file to relabel.
- `new_label s': DLMLabel` — the updated label.

**Server Behavior:**
```
SHARE(caller, file_id, s'):
  f = internal_lookup(file_id)
  if f = NOT_FOUND or caller ∉ EffectiveReaders(f.label):
    return ERROR("Not found")
  s = f.label
  if caller ∉ Owners(s):
    return ERROR("Only an owner may modify the label")
  // Caller may only modify their own entry:
  for each o ∈ Owners(s) where o ≠ caller:
    if Readers(s', o) ≠ Readers(s, o):
      return ERROR("Cannot modify another owner's constraint")
  // No new owners may be added:
  if Owners(s') ⊄ Owners(s):
    return ERROR("Cannot introduce new owners unilaterally")
  f.label = s'
  return OK
```

**Security Argument:** The server enforces the DLM declassification rule: caller may only change their own entry. Two cases arise:

**Case 1: caller adds readers to their own entry.** Formally, s' differs from s only in Readers(s', caller) ⊇ Readers(s, caller). We show EffectiveReaders(s') ⊇ EffectiveReaders(s):

```
EffectiveReaders(s') = ⋂_{o ∈ Owners(s')} Readers(s', o)
                     = Readers(s', caller) ∩ (⋂_{o ≠ caller} Readers(s, o))
                    ⊇ Readers(s, caller)  ∩ (⋂_{o ≠ caller} Readers(s, o))
                     = EffectiveReaders(s)
```

So the set of effective readers only grows: label s' is less or equally restrictive than s. No existing reader loses access; some principals may gain access as authorized by caller.

**Case 2: caller removes themselves from Owners.** Then Owners(s') = Owners(s) \ {caller}. Let A = EffectiveReaders(s) and B = EffectiveReaders(s'). We have:

```
A = ⋂_{o ∈ Owners(s)}         Readers(s, o)
B = ⋂_{o ∈ Owners(s)\{caller}} Readers(s, o)
```

B is the intersection of the same family of sets as A, but with one fewer term. Since A = B ∩ Readers(s, caller), we have A ⊆ B. Therefore EffectiveReaders(s') ⊇ EffectiveReaders(s): removing an owner from the intersection can only increase (or maintain) the effective reader set.

In both cases, since caller is required to already be an owner of s, no other owner's constraint is affected. The DLM rule is satisfied: an owner can only relax their own constraint, never tighten another owner's. No data is transmitted; only permission metadata changes. Hence no illegal flow occurs.

---

## 5.4 UPLOAD_PROGRAM(prog_name: string{⊥}, source: string{⊥}) → prog_id

**Parameters:**
- `prog_name: string{⊥}` — a public name for the program.
- `source: string{⊥}` — annotated source code; every variable x has a declared DLM label annotation γ(x). The source text itself is public.

**Server Behavior:**
```
UPLOAD_PROGRAM(caller, prog_name, source):
  (AST, γ) = parse_with_annotations(source)
  if parse fails: return ERROR("Parse error")
  result = typecheck_DLM(γ, AST)
  if result = FAIL(reason): return ERROR("Type error: " + reason)
  required_delegations = extract_acts_for(AST)
  // required_delegations: list of (owner o, prog_id) pairs
  // that must be registered via DELEGATE before EXECUTE
  pid = fresh_id()
  store program(id=pid, name=prog_name, source=source,
                γ=γ, uploader=caller,
                required_delegations=required_delegations)
  return OK(pid)
```

**The typecheck_DLM procedure:** typecheck_DLM(γ, c) applies the Volpano typing rules with DLM labels in place of {Low, High}. The rules are (from lecture2.pdf, with DLM ⊑):

```
(CONST)   γ ⊢ n : τ              (for any τ)
(VAR)     γ ⊢ x : τ              if γ(x) ⊑ τ
(ARITH)   γ ⊢ e1:τ, e2:τ   ⟹   γ ⊢ (e1 op e2) : τ
(ASSIGN)  γ ⊢ e:τ, γ(x)=τ', τ'⊑τ  ⟹  γ ⊢ (x:=e) : τ'
(COMPOSE) γ ⊢ c1:τ, c2:τ   ⟹   γ ⊢ (c1;c2) : τ
(IF)      γ ⊢ e:τ, c1:τ, c2:τ, τ'⊑τ  ⟹  γ ⊢ (if e c1 c2) : τ'
(WHILE)   γ ⊢ e:τ, c:τ, τ'⊑τ  ⟹  γ ⊢ (while e c) : τ'
```

**Security Argument:** Any program stored by UPLOAD_PROGRAM has passed typecheck_DLM. By the DLM-adapted Non-Interference theorem (Section 3.3), such a program c satisfies: for any principal q, for any two q-equivalent memories μ1 ~q μ2 (agreeing on all variables x with q ∈ EffectiveReaders(γ(x))), if c terminates on both, the output memories are also q-equivalent.

This guarantees that the program cannot move information from a variable with label s to a variable with label s' unless s ⊑ s', i.e., unless EffectiveReaders(s') ⊆ EffectiveReaders(s). In particular, the program cannot leak data to a principal not authorized to see it, through either explicit assignments or implicit control-flow dependencies.

**Model boundary:** Volpano's Non-Interference applies to the observable output of terminating executions. It does not cover information leaked via timing side channels (e.g., loop termination time, memory-access patterns). Preventing such side channels requires additional mechanisms (e.g., constant-time execution environments) outside the scope of this design. We note this as a known limitation.

---

## 5.5 EXECUTE(prog_id: int{⊥}, input_file_id: int{⊥}, output_label: DLMLabel) → file_id

**Parameters:**
- `prog_id: int{⊥}` — the program to execute.
- `input_file_id: int{⊥}` — the input file.
- `output_label s_out: DLMLabel` — the label to assign to the output file.

**Server Behavior:**
```
EXECUTE(caller, prog_id, input_file_id, s_out):
  prog = internal_lookup(prog_id)
  f_in = internal_lookup(input_file_id)
  if prog = NOT_FOUND or f_in = NOT_FOUND:
    return ERROR("Not found")

  // Check 1: caller can read the input
  if caller ∉ EffectiveReaders(f_in.label):
    return ERROR("Access denied to input file")

  s_in = f_in.label

  // Compute owners whose constraint is relaxed in s_out relative to s_in
  dropped_owners  = Owners(s_in) \ Owners(s_out)
  relaxed_owners  = {o ∈ Owners(s_in) ∩ Owners(s_out) |
                     Readers(s_out, o) ⊋ Readers(s_in, o)}
  declassified_owners = dropped_owners ∪ relaxed_owners

  if declassified_owners = ∅:
    // No declassification: output must be at least as restrictive as input
    if not (s_in ⊑ s_out):
      return ERROR("Output label is less restrictive than input; no delegation provided")
  else:
    // Declassification path: each relaxed owner must have delegated to this program
    for each o ∈ declassified_owners:
      if not server_has_delegation(o, prog_id):
        return ERROR("Missing delegation from owner " + o)
    // s_out must not introduce new owners absent from s_in
    if Owners(s_out) \ Owners(s_in) ≠ ∅:
      return ERROR("Cannot introduce new owners in output label")

  // Run in isolated sandbox
  result_data = sandbox_execute(prog.source, f_in.data)
  fid_out = fresh_id()
  store file(id=fid_out, data=result_data, label=s_out, uploader=caller)
  return OK(fid_out)
```

**Security Argument:**

**Check 1 — Caller authorization.** The caller must be in EffectiveReaders(f_in.label). This ensures the caller is legitimately authorized to supply this input to a program.

**Check 2a — No-declassification path.** When declassified_owners = ∅, we require s_in ⊑ s_out. By the DLM ordering definition, s_in ⊑ s_out means: (i) Owners(s_in) ⊆ Owners(s_out), and (ii) Readers(s_out, o) ⊆ Readers(s_in, o) for every o ∈ Owners(s_in). Therefore:

```
EffectiveReaders(s_out) = ⋂_{o ∈ Owners(s_out)} Readers(s_out, o)
                        ⊆ ⋂_{o ∈ Owners(s_in)} Readers(s_out, o)   [by (i): Owners(s_in) ⊆ Owners(s_out)]
                        ⊆ ⋂_{o ∈ Owners(s_in)} Readers(s_in, o)    [by (ii): Readers(s_out,o) ⊆ Readers(s_in,o)]
                        = EffectiveReaders(s_in)
```

So the output is at least as restricted as the input. The program was verified by typecheck_DLM, so by Non-Interference (Section 3.3), it cannot write to a variable whose effective readers are a strict superset of the source variable's effective readers. Combined with EffectiveReaders(s_out) ⊆ EffectiveReaders(s_in), no principal unauthorized by s_in can access the output.

**Check 2b — Declassification path.** For each owner o ∈ declassified_owners, we require a registered delegation. The check `Owners(s_out) \ Owners(s_in) ≠ ∅ → ERROR` guards against new owners being introduced in s_out: adding a new owner would tighten the output label (wrong direction) and is therefore rejected. Every relaxation of an existing owner's constraint in s_in requires that owner's explicit consent via DELEGATE. Owners not in declassified_owners have Readers(s_out, o) ⊆ Readers(s_in, o) (their constraints are not relaxed), so those owners' authorization is fully respected.

Together, these checks implement the full DLM declassification policy: an owner's constraint can only be relaxed with that owner's explicit consent.

**Sandbox guarantee.** The Volpano type analysis reasons about information flow between the program's labeled variables. For this to be meaningful, the execution environment must enforce that the program receives input exclusively through its declared input variable (bound to f_in.data) and produces output exclusively through its return value — it must not be able to directly access server storage, invoke other API commands, or read any other file. The sandbox_execute procedure enforces exactly this: the program runs in an isolated process with no access to the server's file store, no network access, and no shared memory with the server. Its only interface to the outside world is the single input value and the single returned output value. Under this isolation, the program's labeled variables are the complete information universe the type analysis covers, and the Non-Interference guarantee of Section 3.3 applies without gaps.

---

## 5.6 DELEGATE(prog_id: int{⊥}, owner: Principal{⊥}) → OK

**Parameters:**
- `prog_id: int{⊥}` — the program to receive delegated authority.
- `owner: Principal{⊥}` — the owner granting the delegation (must equal caller).

**Server Behavior:**
```
DELEGATE(caller, prog_id, owner):
  if caller ≠ owner:
    return ERROR("Only the owner can delegate their own authority")
  if internal_lookup(prog_id) = NOT_FOUND:
    return ERROR("Program not found")
  store delegation(owner=caller, prog_id=prog_id)
  return OK
```

**Security Argument:** No data moves. The server records the fact that owner has consented to prog_id acting on their behalf. The check caller = owner ensures that a user cannot grant another user's authority. This metadata is only consumed by EXECUTE (Section 5.5, Check 2b), which uses it to verify that each relaxed owner has consented. The DLM rule is upheld: only an owner can relax their own constraint.

---

## 5.7 LIST_MY_FILES() → list of (file_id, filename, label)

**Server Behavior:**
```
LIST_MY_FILES(caller):
  result = []
  for each file f in storage:
    if caller ∈ EffectiveReaders(f.label):
      result.append((f.id, f.filename, f.label))
  return OK(result)
```

**Security Argument:** This command returns only files for which caller ∈ EffectiveReaders(f.label), i.e., only files the caller is authorized to know about and read. The label of each returned file is also revealed, but since the caller is an effective reader, they are already authorized by every owner of that file. File IDs and filenames of files not in the result are not revealed. This is consistent with READ's unified error (Section 5.2): both commands reveal file existence if and only if caller ∈ EffectiveReaders(f.label).

---

## 5.8 LIST_PUBLIC_FILES(user: Principal{⊥}) → list of (file_id, filename)

**Parameters:**
- `user: Principal{⊥}` — the user whose files the caller wants to browse.

**Server Behavior:**
```
LIST_PUBLIC_FILES(caller, user):
  result = []
  for each file f in storage where f.uploader = user:
    if caller ∈ EffectiveReaders(f.label):
      result.append((f.id, f.filename))
  return OK(result)
```

**Security Argument:** The filter caller ∈ EffectiveReaders(f.label) is identical to the one used in LIST_MY_FILES and READ. The command scopes the query to files uploaded by a specific user, providing a user-browsing perspective (e.g., "show me Hospital's files I can access") that LIST_MY_FILES does not directly support without client-side post-filtering. The security argument is the same as for LIST_MY_FILES: a file entry appears in the result if and only if the caller is an effective reader of that file's label, which is the DLM authorization condition. No information about unauthorized files — neither their existence nor their labels — is revealed. Only (file_id, filename) pairs are returned rather than the full label, since the label is not needed for discovery; callers who need the label may use READ or LIST_MY_FILES.

---

# 6. Summary of Security Guarantees

*[Author: Student C]*

We claim: for any sequence of API calls by any combination of (potentially dishonest) users and (potentially malicious) uploaded programs, no information flows from a data item with label s to a principal q unless q ∈ EffectiveReaders(s) and every owner in Owners(s) has authorized this.

The argument is compositional across commands:

- **UPLOAD** stores data without releasing it; label ownership is enforced. (Section 5.1)
- **READ** releases data only to EffectiveReaders; file existence is not revealed to unauthorized callers via the unified error. (Section 5.2)
- **SHARE** allows only the caller-owner to relax their own constraint, proven by set-inclusion arguments to only increase EffectiveReaders. Other owners are unaffected. (Section 5.3)
- **UPLOAD_PROGRAM** type-checks programs against DLM-instantiated Volpano rules. The DLM-adapted Non-Interference theorem (Section 3.3) guarantees that stored programs cannot leak data beyond their variable label annotations. (Section 5.4)
- **EXECUTE** enforces s_in ⊑ s_out in the no-declassification case (proven to imply EffectiveReaders(s_out) ⊆ EffectiveReaders(s_in)), and requires explicit per-owner delegation for each relaxed constraint in the declassification case. Combined with the program's Non-Interference property and sandbox isolation, no unauthorized flow is possible. (Section 5.5)
- **DELEGATE** records owner consent; no data flows. Prevents unauthorized declassification. (Section 5.6)
- **LIST_MY_FILES** returns only files to which the caller has EffectiveReader access; consistent with READ's unified error. (Section 5.7)
- **LIST_PUBLIC_FILES** applies the same EffectiveReaders filter scoped to a specific uploader; existence of unauthorized files is not revealed. (Section 5.8)

The foundational guarantee rests on Section 3.3: the DLM label set is a lattice (Section 3.2), the Volpano type rules apply to any lattice, and the Non-Interference proof goes through with the DLM-adapted definition of q-equivalence. The key technical link — that τ' ⊑ τ implies EffectiveReaders(τ') ⊆ EffectiveReaders(τ) — was derived explicitly from the DLM ordering definition, closing the main gap between the original Volpano theorem and its application in our multi-user DLM setting.
