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
