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
