# Lab Logbook: Week 2 (Dolev and Yao Model)

## 1. Protocol Development Overview (AnB Version: OpenAuth_v1)
This week's goal is to implement a basic authentication and photo-sharing protocol.

### AnB Implementation (`week2_v1.AnB` Snapshot):
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

## 2. Core Idea
The main idea is based on an authorization token model. A first sends a request to P in $M_1$, and P forwards that request to B in $M_2$. B then returns an authorization token $Token$. After that, A signs the token and sends it back to B in $M_4$, which is meant to prove that P has been authorized to access the photos.

In the model, $Photos$ is represented as an encrypted payload of type `Number`. It is sent by B in $M_5$ after being encrypted with P's public key.

## 3. Modeling Considerations and Simplifications
We assume a simplified public-key setting in which all agents, namely A, B, and P, already possess public and private key pairs and already know one another's public keys. At this stage, the model does not include an identity provider or any certificate distribution mechanism.

For the authentication phase, we mainly use digital signatures such as `inv(pk(X))` rather than encryption. This choice makes the protocol easier to debug and keeps the model relatively efficient while still expressing identity verification and message integrity.

## 4. Problems Encountered and Analysis
When we first ran OFMC, we encountered a syntax error because we had accidentally added an extra semicolon (`;`) at the end of the `Goals` section. After debugging, we removed the unnecessary symbol and the tool ran correctly.

OFMC then reported an attack, as shown below.

### Full OFMC Output
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
i learns: x311   ← Photos leaked
```

### Attack Trace Explanation

In the attack trace, `x32` denotes the honest agent playing the role of P, `x311` denotes `Photos`, and `i` denotes the intruder.

The attack begins when the intruder impersonates A and sends a request to P, but sets B's identity to P itself, so the message effectively uses `A=i` and `B=P`. P accepts this request and forwards it to what it believes is B, although that is actually P itself, and the intruder intercepts the forwarded message. The intruder then skips the token exchange in M3 and M4 and directly sends a forged photo message to P as if it came from B. Because the intruder chooses the value of `Photos` as `x311`, the secrecy goal is violated from the start, since the intruder already knows that value.

### Root Cause Analysis

The first weakness is that P never verifies whether M5 actually comes from a legitimate source. P simply receives $M_1$, sends $M_2$, and then waits for $M_5$. When the photos arrive, there is no mechanism that checks whether the sender has really completed the authorization flow in M3 and M4. As a result, the intruder can bypass B entirely and send M5 directly to P.

The second weakness is that the identity of B is not properly bound in the protocol. In $M_1$, the intruder sets `B` to `P` itself, written as `B = x32 = P`. P does not test whether that choice is sensible and therefore forwards the request to itself. The intruder intercepts that behavior and uses it to complete the attack.

The third weakness is that `Photos` has no binding protection. The term `{Photos}pk(P)` encrypts only the content, but it does not prove who created the message. Anyone who knows `pk(P)`, including the intruder, can construct such a message with any chosen value and send it to P. Since the intruder chooses the value, the intruder also knows it, so secrecy cannot hold.

## 5. Follow-up Improvement Plan
For the next step, we plan to introduce an identity provider so that the model can reflect key distribution in a more realistic way. We also want to study possible defenses against replay attacks and consider encrypting the transmission of $Token$.

# Lab Logbook: Week 3 (Lazy Intruder and Identity Provider)

## 1. Protocol Development Overview (AnB Version: OpenAuth_v3_IdP)
This week, we extended the Week 2 version by introducing an identity provider, or IdP. We also replaced A's public and private key pair with a password-based authentication step so that the protocol would be closer to a realistic identity verification setting.

### AnB Implementation (`week3_v1.AnB` Snapshot):
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

## 2. Changes from Week 2
The main change from Week 2 is the introduction of a fourth participant, `IdP`, which is responsible for issuing an authorization statement. Instead of having A sign directly for P, A now first obtains a signed token from the IdP and then forwards that token to P.

At the same time, A no longer has `inv(pk(A))` in its initial knowledge, so A cannot generate signatures on its own. Instead, we model a shared password between A and the IdP as `pw(A)`. A proves its identity to the IdP by sending this password in the first message. Because of this redesign, the protocol structure changes from the previous five-step form. The new first step is the authentication exchange between A and the IdP, and after the IdP issues the certificate, the later authorization flow toward P and B continues in an updated form.

## 3. Modeling Considerations
For the password, we use `Function pw` rather than a plain `Number`. In OFMC's AnB language, the `Knowledge` section only accepts agent variables and function applications over agents, such as `pk(A)` or `inv(pk(A))`, and it does not allow a raw `Number` value to be placed there directly. For that reason, the password must be modeled as `pw(A)`, which represents a password specific to A and can appear in the initial knowledge of both A and the IdP. In this model, the password is used only as an authentication credential in the first message. It is not used as an encryption key or a signing key, which is also closer to how passwords are used in practice.

When the IdP endorses A's request, it receives the request together with `pw(A)` as proof of identity and then signs the tuple `{A,B,P,ReqA,N_A}` using `inv(pk(IdP))`. This produces the authorization token. A forwards that token unchanged to P, and P verifies it using the known public key `pk(IdP)`, so P can trust the token content.

In the initial design, we also considered using a constant called `Auth_for_P_from_A` to mark the purpose of the token. However, OFMC does not support a `Constant` type, and values of type `Number` cannot be placed directly in the knowledge section either. In the end, we omitted that extra marker because the signed message already contains A, B, P, and `ReqA`, which is enough to express the intended authorization meaning.

When P forwards the request to B, P uses a nested signature. More precisely, P signs the IdP token together with a fresh value `N_P_req` by using `inv(pk(P))`. B can then verify with `pk(P)` that the outer message comes from P, and it can verify with `pk(IdP)` that the inner token is genuinely issued by the IdP. The purpose of introducing `N_P_req` is to provide freshness for this specific request and reduce replay risk.

## 4. Problems Encountered and Analysis
During modeling, we encountered several AnB syntax issues. Comments written with `--` had to be removed because AnB does not support that comment style. Expressions of the form `{msg}_{key}` were also invalid, because the correct syntax is `{msg}key` without an underscore. Angle brackets such as `<A,B,P>` could not be used for message concatenation, so we replaced them with plain comma-separated terms. We also found that OFMC does not support a `Constant` type, which is why we switched to function-based modeling where necessary. Another issue was that a password written as a `Number` could not be placed in the knowledge section, so we replaced it with `Function pw` and used the form `pw(A)`. Finally, the `Goals` section originally ended with a semicolon, which caused a parsing error, and that symbol had to be removed.

OFMC then reported an attack, as shown below.

### Full OFMC Output
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

According to the reached state, `x35` refers to the honest agent P, `x37` refers to the honest agent B, `x38` stands for some agent A, `x210` and `x211` correspond to `ReqA` and `N_A`, `x313` corresponds to `Photos`, and `NPreq(1)` is the fresh `N_P_req` generated by P. The crucial observation is that `pk(i)` appears in P's state where the IdP public key should be. This means that, in this attack instance, P's `IdP` variable has been instantiated as the intruder `i`.

The attack starts when the intruder sends P a fake certificate signed with `inv(pk(i))`, pretending that it is an IdP-signed token. This matches the protocol step `A->P: {A,B,P,ReqA,N_A}inv(pk(IdP))`. Because P's `IdP` variable has been bound to `i`, P verifies the signature using `pk(i)` and therefore accepts the forged token. At that point, the honest A, B, and IdP have not participated at all.

After accepting the fake token, P generates a fresh value `NPreq(1)` and sends the nested signed request toward what it believes is B. This corresponds to `P->B: {{...}inv(pk(IdP)),N_P_req}inv(pk(P))`. The intruder intercepts that message on the network, which is possible in the Dolev-Yao model because the intruder controls all communication.

The intruder then impersonates B and sends `{x313}pk(x35)` to P, where `x313` is a value chosen by the intruder. This corresponds to `B->P: {Photos}pk(P)`. P decrypts the message with `inv(pk(P))` and accepts it as the photos. Since `x313` was chosen by the intruder, the intruder already knows the value, so the secrecy goal `Photos secret between B,P` is violated. In effect, B never participates, and P receives a fake photo payload.

The main cause of the attack is that the identity of the IdP is not fixed securely. In P's initial knowledge, `IdP` is just an agent variable. Under OFMC's Dolev-Yao model, the intruder `i` is also a valid agent and owns `pk(i)` and `inv(pk(i))`. When the role of P is instantiated, the `IdP` variable may therefore be bound to any agent, including the intruder. Once `IdP = i`, the intruder can issue a certificate that P considers valid.

There is also a secondary weakness in B's response. When B sends `{Photos}pk(P)`, the message does not include `N_P_req`, so P cannot verify that the received photos are actually a response to the earlier request. Anyone who knows `pk(P)` can construct such a ciphertext and send it to P. The essence of the attack is that it is carried out entirely between the intruder and P, while the honest A, B, and IdP are bypassed. The intended trust chain from A to IdP to P to B can therefore be short-circuited by the intruder when the IdP identity is not fixed.

## 5. Follow-up Improvement Plan
For the next step, we need to solve the IdP identity-binding problem. Before P accepts a token, there should be a mechanism that ensures the token really comes from the legitimate IdP rather than from any agent that simply owns a key pair.

We also need to study how to bind B's response to P's request `N_P_req` so that the intruder cannot impersonate B and replace the photo content. In addition, we may consider introducing mutual authentication or a nonce-challenge mechanism next week in order to address these weaknesses more systematically.

# Lab Logbook: Week 4 (Secure Implementation and Typing)

## 1. Protocol Development Overview (AnB Version: OpenAuth_v4_IdP)

The goal of this week was to extend the protocol developed in Week 3 by introducing message formats to eliminate type confusion. In addition, the assumption that agent (A) initially knows all public keys was removed in order to make the protocol closer to a realistic authentication scenario. Finally, the protocol was verified to be **Type-Flaw Resistant**.

### AnB Implementation (`week4_v1.AnB` Snapshot)

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

---

### AnB Implementation (`week4_keylookup.AnB` Snapshot)

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

---

### AnB Implementation (`week4_v2.AnB` Snapshot)

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

---

# 2. Key Changes from Week 2

* **Introduction of Message Formats**

  Following the method presented in the lecture slides, format tags were introduced for each message. All raw concatenations were replaced by structured messages with explicit format labels. This prevents type confusion attacks.

* **Removing the Assumption that A Knows All Public Keys**

  In the initial knowledge of (A), the public keys of all agents were removed. Instead, a separate protocol was designed that allows (A) to query the public key of another participant from the identity provider when needed.

* **Verification of Type-Flaw Resistance**

  According to the definition introduced in the lecture, both the main protocol and the key lookup sub-protocol were verified to be **Type-Flaw Resistant**.

---

# 3. Problems Encountered and Analysis

## 3.1 Observations During Code Execution (OFMC Output)

### OFMC Output

```
ofmc: pk(X) is never known by X
CallStack (from HasCallStack)
```

### Analysis

In the sub-protocol, the queried agent was not included in the initial knowledge of (A).

---

### OFMC Output

```
SUMMARY: ATTACK_FOUND
GOAL: weak_auth
```

### Analysis

A weak authentication attack was detected. After inspection, the issue was identified as the absence of the receiver identity (A) in the response message. To fix this problem, the receiver identity and the nonce (N_A) generated by (A) were added to the message. This also ensures protection against replay attacks.

---

### Sub-protocol OFMC Output

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

---

### Main Protocol OFMC Output

```
SUMMARY:
  ATTACK_FOUND
GOAL:
  secrets
```

### Attack Trace

```
i -> (x39,1): {f2,x42,x41,x39,x210,x211}_inv(pk(i))
(x39,1) -> i: {f3,{f2,x42,x41,x39,x210,x211}_inv(pk(i)),NPreq(1)}_inv(pk(x39))
i -> (x39,1): {f4,x313}_(pk(x39))

i can produce secret x313
```

Secret leaked: **x313**

---

### Variable Mapping (From Reached State)

| OFMC Variable | Meaning                               | Reason                          |
| ------------- | ------------------------------------- | ------------------------------- |
| x39           | Honest agent P                        | `state_rP(x39,...)`             |
| x41           | Honest agent B                        | `contains(secrecyset(...),x41)` |
| x42           | Some agent A                          | position of A in message M3     |
| x210,x211     | ReqA, N_A                             | fresh numbers                   |
| x313          | Photos                                | secret value                    |
| NPreq(1)      | nonce generated by P                  |                                 |
| pk(i)         | "IdP public key" from P's perspective |                                 |

---

### Key Observation

In the state of (P), the term `pk(i)` appears in the position corresponding to the **public key of IdP**. This means that during this attack instance, the variable **IdP was instantiated as the intruder (i)**.

---

### Attack Explanation

**Step 1**

The intruder sends a forged "IdP certificate":

```
i -> P: {f2,...}_inv(pk(i))
```

Since (P)'s IdP variable is instantiated as (i), (P) verifies the signature using (pk(i)), and therefore accepts it as valid.

---

**Step 2**

(P) generates a nonce (N_P_req) and forwards the request to (B).

The intruder intercepts this message.

---

**Step 3**

The intruder impersonates (B) and sends a message encrypted with (pk(P)):

```
i -> P: {f4,x313}_pk(P)
```

---

**Step 4**

Since the intruder chose (x313), the intruder already knows the value of **Photos**.

This violates the security goal:

```
Photos secret between B,P
```

---

### Root Cause

#### 1. Identity Provider Not Fixed

The identity provider (IdP) was modeled as a variable agent. In the Dolev-Yao model, the intruder is also an agent and has its own key pair. Therefore the intruder can instantiate the variable `IdP`.

#### 2. Missing Binding Between Request and Response

The message from (B) did not include the nonce (N_P_req). Therefore (P) cannot verify that the received photos correspond to the request.

---

# Final Fix

### 1. Fixing the Identity Provider

The identity provider name was changed from `IdP` to `idp`, making it a fixed agent. This prevents the intruder from impersonating the identity provider.

---

### 2. Protecting Communication Between B and P

The final message from (B) to (P) is now signed by (B) and encrypted using (P)'s public key.

---

### 3. Adding Role Constraints

```
where B != P
```

This prevents unrealistic instantiations where (B) and (P) are the same agent.

---

### 4. Simplifying Message Structures

```
f3(B, P, {f2(B, P, ReqA, N_A)}inv(pk(idp)), N_P_req)

f4(B, P, N_P_req, Photos)
```

The identities and nonces provide proper session binding and prevent replay attacks.

---

### Final OFMC Output

```
SUMMARY:
  NO_ATTACK_FOUND
GOAL:
  as specified
```

---

# 4. Special Task: Proving the Protocol is Type-Flaw Resistant

## Main Protocol

### Step 1 — Extract the SMP

1. (m_1 = {f1(X_1,X_2,N_1,N_2,W_1)}_{pk})

2. (m_2 = {f2(X_1,X_2,N_1,N_2)}_{sk})

3. (m_3 = {f2(X_1,X_2,N_1,N_2)}_{sk})

4. (m_4 = {f3(X_1,X_2,M_1,N_3)}_{sk})

5. (m_5 = {{f4(X_1,X_2,N_3,N_4)}*{sk}}*{pk})

SMP = { m₁, m₂, m₃, m₄, m₅ }

---

### Step 2 — Pairwise Unification

* (m_1) cannot unify with any other message due to different encryption layers and format tags.
* (m_2) vs (m_4): different formats and argument structures.
* (m_2) vs (m_5): different encryption nesting.
* (m_4) vs (m_5): different encryption structures.
* (m_2) vs (m_3): identical structures → unifiable.

---

### Step 3 — Type Consistency

The only unifiable pair is (m_2) and (m_3), and they have identical types. Therefore the protocol satisfies the definition of **Type-Flaw Resistance**.

---

## Sub-protocol

### Step 1 — SMP

1. (m_1 = f1(X_1,X_2,N_1))

2. (m_2 = {f2(X_1,X_2,T_1,N_1)}_{sk})

SMP = { m₁, m₂ }

---

### Step 2 — Unification

The two messages have:

* different format tags
* different encryption structures
* different number of parameters

Thus they **cannot unify**.

---

### Step 3 — Conclusion

Since no two messages unify with mismatching types, the sub-protocol also satisfies **Type-Flaw Resistance**.

---

# Week 5 Logbook

## Protocol Snapshot

### Main Protocol

```AnB
Protocol: OpenAuth_final

Types:
  Agent A,B,P,idp;
  Number ReqA,Photos,N_A,N_P_req,N_B;
  Function pk,pw;
  Format f1, f2, f3, f4, f5, f6;

Knowledge:
  A: A,B,P,idp,pk(idp),pw(A);
  B: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(B));
  P: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(P));
  idp: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(idp)),pw(A)
where B!=P

Actions:
  A->idp: {f1(A, B, P, ReqA, N_A, pw(A))}pk(idp)
  idp->A: {f2(A, B, P, ReqA, N_A)}inv(pk(idp))
  A->P: {f2(A, B, P, ReqA, N_A)}inv(pk(idp))
  P->B: f3(B, P, {f2(A, B, P, ReqA, N_A)}inv(pk(idp)))
  B->P: {f4(B, P, N_B)}pk(P)
  P->B: {f5(B, P, {f2(A, B, P, ReqA, N_A)}inv(pk(idp)), N_P_req, N_B)}inv(pk(P))
  B->P: {{f6(B, P, N_P_req, N_B, Photos)}inv(pk(B))}pk(P)

Goals:
  Photos secret between B,P
  P authenticates B on Photos,N_P_req,N_B
  B authenticates P on N_P_req,N_B
```
### Main Protocol - TLS channels

```AnB
Protocol: OpenAuth_Week5_TLS

Types:
  Agent A,B,P,idp;
  Number ReqA,Photos,N_A,N_P_req,N_B;
  Function pk,pw;
  Format f1, f2, f3, f4, f5, f6;

Knowledge:
  A: A,B,P,idp,pk(idp),pw(A);
  B: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(B));
  P: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(P));
  idp: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(idp)),pw(A)
where B!=P

Actions:
  [A] *->* idp: f1(A, B, P, ReqA, N_A, pw(A))
  idp *->* [A]: {f2(A, B, P, ReqA, N_A)}inv(pk(idp))
  [A] *->* P: {f2(A, B, P, ReqA, N_A)}inv(pk(idp))
  [P] *->* B: f3(B, P, {f2(A, B, P, ReqA, N_A)}inv(pk(idp)))
  B *->* [P]: f4(B, P, N_B)
  [P] *->* B: {f5(B, P, {f2(A, B, P, ReqA, N_A)}inv(pk(idp)), N_P_req, N_B)}inv(pk(P))
  B *->* [P]: {f6(B, P, N_P_req, N_B, Photos)}inv(pk(B))

Goals:
  Photos secret between B,P
  P authenticates B on Photos,N_P_req,N_B
  B authenticates P on N_P_req,N_B
```

### Sub Protocol - TLS channels
```AnB
Protocol: KeyLookup_v5_TLSChannels

Types:
  Agent A,X,idp;
  Number N_A;
  Function pk;
  Format f1,f2;

Knowledge:
  A: A,X,IdP,pk(idp);
  IdP: IdP,A,X,pk(idp),inv(pk(idp)),pk(X);

Actions:

  [A] *->* idp: f1(A,X,N_A)
  IdP *->* [A]: f2(A,X,pk(X),N_A)

Goals:
  A authenticates idp on pk(X),N_A
```


## Changes from previous version

In Week 5, the protocol was revised to achieve the goal of preventing replay attacks，while establishing model **TLS-style pseudonymous secure channels** and to simplify the protocol while preserving its security goals.




### 1. Add `A` to the token.

The original token is:

```anb
{f2(B, P, ReqA, N_A)}inv(pk(idp))
```

Now changed to:

```anb
{f2(A, B, P, ReqA, N_A)}inv(pk(idp))
```

Thus, the token is explicitly bound to:

- `A`：Authorized Initiator
- `B`：Target Server
- `P`：Authorized Service
- `ReqA`：Authorization Request Content
- `N_A`：The nonce of this authorization request

The purpose of this is to make the authorization semantics more complete, clearly expressing that `A` authorizes `P` to access the resource scope represented by `ReqA` on `B`.

### 2. Add a challenge-response mechanism between `P` and `B`.

Originally, there were only two steps between `P` and `B`:

```anb
P->B: {f3(B, P, token, N_P_req)}inv(pk(P))
B->P: {{f4(B, P, N_P_req, Photos)}inv(pk(B))}pk(P)
```

Now changed to four steps:

```anb
P->B: f3(B, P, token)
B->P: {f4(B, P, N_B)}pk(P)
P->B: {f5(B, P, token, N_P_req, N_B)}inv(pk(P))
B->P: {{f6(B, P, N_P_req, N_B, Photos)}inv(pk(B))}pk(P)
```

Added:

- `N_B`：Challenge nonce generated by `B`

The purpose of this is to let `B` issue a fresh challenge before processing the final request, requiring `P` to sign and return the challenge together with the token and the request nonce, thereby reducing the possibility of replay attacks.

### 3. Split message format

Original format:

```anb
Format f1, f2, f3, f4;
```

Now changed to:

```anb
Format f1, f2, f3req, f3chal, f3resp, f4;
```

That is, the original `f3` is split into three different messages:

- `f3`：Initial Request
- `f4`：Server Challenge
- `f5`：Client's Response to the Challenge

The purpose of this is to make the message semantics at different stages clearer and reduce the risk of message confusion.

### 4. Strengthen Final Response Binding

The original final response is:

```anb
{{f4(B, P, N_P_req, Photos)}inv(pk(B))}pk(P)
```

Now changed to:

```anb
{{f6(B, P, N_P_req, N_B, Photos)}inv(pk(B))}pk(P)
```

That is, the challenge `N_B` issued by `B` is also included in the final response. In this way, `P` can not only check whether the response corresponds to its own request `N_P_req`, but also verify whether the response belongs to the current challenge-response session.

### 5. Add stronger authentication goals

Originally there was only one goal:

```anb
Photos secret between B,P
```

Now increased to:

```anb
Photos secret between B,P
P authenticates B on Photos,N_P_req,N_B
B authenticates P on N_P_req,N_B
```

The two newly added goals are used to verify:

- Whether the response accepted by `P` indeed comes from `B` and is bound to the current request and the current challenge.
- Whether the request accepted by `B` indeed comes from a genuine `P` session and is bound to the current challenge.

### 6. Introducing pseudonymous secure channels

The communication between **A and idp**, between **A and P**, and between **B and P**  was replaced with pseudonymous secure channels.

---



# Modeling Considerations

### TLS abstraction

TLS communication is modeled using **pseudonymous secure channels** instead of explicitly modeling encryption and key exchange.

This abstraction assumes that confidentiality and integrity are already provided by the transport layer.


---

## Problems Encountered

### Loss of authentication when overusing channels

An early design replaced the `P → B` communication with pseudonymous channels.
However, this prevented `B` from verifying that the request originated from the authorized service `P`.
To solve this issue, explicit signatures were retained for the communication between `P` and `B`.

### Mix-up risks during protocol simplification

When simplifying the protocol messages, removing identity bindings created potential mix-up attacks where messages from different sessions could be incorrectly combined.
Including `B` and `P` in the message formats resolved this problem.

### Long verification time in OFMC

During verification, the protocol required a very long running time in OFMC.
This is caused by the **state-space explosion problem**, which arises from multiple sessions and nested cryptographic structures.

Several steps were taken to mitigate this issue:

* simplifying message formats
* removing unnecessary fields

Although these optimizations reduced the search space, verification for higher session bounds still required significant time.

---

# Week 6: Guessable Password

For Week 6, we considered the password between `A` and `idp` as a **guessable secret**. The project explicitly requires that the password must **not** be used as an encryption key, and our protocol satisfies this requirement, since `pw(A)` only appears as login data and is never used to encrypt other messages.

To model this scenario in OFMC, we extend the protocol specification by declaring the password as a guessable secret:

```AnB
pw(A) guessable secret between A,idp
```

This declaration instructs the model checker to treat the password as a **low-entropy secret that the intruder may guess**. In the symbolic model, this allows OFMC to check whether an attacker could verify password guesses using information observable on the network.

The protocol used for this verification is the following.

```AnB
Protocol: OpenAuth_Week6_Guessable

Types:
  Agent A,B,P,idp;
  Number ReqA,Photos,N_A,N_P_req,N_B;
  Function pk,pw;
  Format f1, f2, f3, f4, f5, f6;

Knowledge:
  A: A,B,P,idp,pk(idp),pw(A);
  B: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(B));
  P: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(P));
  idp: A,B,P,idp,pk(B),pk(P),pk(idp),inv(pk(idp)),pw(A)
where B!=P

Actions:
  [A] *->* idp: f1(A, B, P, ReqA, N_A, pw(A))
  idp *->* [A]: {f2(A, B, P, ReqA, N_A)}inv(pk(idp))
  [A] *->* P: {f2(A, B, P, ReqA, N_A)}inv(pk(idp))
  [P] *->* B: f3(B, P, {f2(A, B, P, ReqA, N_A)}inv(pk(idp)))
  B *->* [P]: f4(B, P, N_B)
  [P] *->* B: {f5(B, P, {f2(A, B, P, ReqA, N_A)}inv(pk(idp)), N_P_req, N_B)}inv(pk(P))
  B *->* [P]: {f6(B, P, N_P_req, N_B, Photos)}inv(pk(B))

Goals:
  Photos secret between B,P
  P authenticates B on Photos,N_P_req,N_B
  B authenticates P on N_P_req,N_B
  pw(A) guessable secret between A,idp
```

In the final protocol, the password is sent only in the login message

```AnB
[A] *->* idp: f1(A, B, P, ReqA, N_A, pw(A))
```

which is transmitted over a **pseudonymous secure channel**. The lecture notes describe this notation as modeling a TLS connection where only the server is authenticated, and it is explicitly suggested for modeling password-based logins.

Therefore, the attacker does not observe any reusable public transformation of the password that could support an **offline guessing attack**. In particular:

* the password is never used as an encryption key,
* the password is never used in a cryptographic function that appears in network messages,
* the only occurrence of the password is inside the login message sent through a secure channel.

As a result, even if the intruder guesses candidate passwords, there is **no observable network data** that allows verifying the correctness of a guess.

The confidentiality of `Photos` does not depend on the entropy of the password. Instead, it relies on:

* the authorization token signed by `idp`,
* the signature of `P` on the request sent to `B`,
* the signed response from `B` containing the photos.

Since pseudonymous channels do not guarantee freshness, we still include the nonce `N_P_req` in the protocol to bind the response to the request and prevent replay attacks.

This analysis does not claim resistance against unrestricted **online guessing attacks** against the identity provider. Rather, it shows that the protocol remains secure against **passive/offline password guessing** in the symbolic model, even when the password itself is treated as a guessable secret.
