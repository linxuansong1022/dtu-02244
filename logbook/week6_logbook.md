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
