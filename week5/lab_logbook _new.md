# Week 5 Logbook

## Protocol Snapshot 

### 主协议

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
### 主协议-TLSchannels

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

### 子协议
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




### 1. 在 token 中加入 `A`

原来的 token 为：

```anb
{f2(B, P, ReqA, N_A)}inv(pk(idp))
```

现在改为：

```anb
{f2(A, B, P, ReqA, N_A)}inv(pk(idp))
```

这样 token 显式绑定了：

- `A`：授权发起者
- `B`：目标服务器
- `P`：被授权的服务
- `ReqA`：授权请求内容
- `N_A`：本次授权请求的 nonce

这样做的目的是让授权语义更完整，明确表达“是 `A` 授权 `P` 去访问 `B` 上由 `ReqA` 表示的资源范围”。

### 2. 在 `P` 和 `B` 之间加入 challenge-response

原来的 `P` 和 `B` 之间只有两步：

```anb
P->B: {f3(B, P, token, N_P_req)}inv(pk(P))
B->P: {{f4(B, P, N_P_req, Photos)}inv(pk(B))}pk(P)
```

现在改为四步：

```anb
P->B: f3req(B, P, token)
B->P: {f3chal(B, P, N_B)}pk(P)
P->B: {f3resp(B, P, token, N_P_req, N_B)}inv(pk(P))
B->P: {{f4(B, P, N_P_req, N_B, Photos)}inv(pk(B))}pk(P)
```

新增了：

- `N_B`：由 `B` 生成的 challenge nonce

这样做的目的是让 `B` 在处理最终请求前先发出一个新鲜挑战，要求 `P` 把该挑战连同 token 和请求 nonce 一起签回，从而减少重放攻击的可能。

### 3. 拆分消息格式

原来格式为：

```anb
Format f1, f2, f3, f4;
```

现在改为：

```anb
Format f1, f2, f3req, f3chal, f3resp, f4;
```

也就是将原来的 `f3` 拆分成三种不同消息：

- `f3req`：初始请求
- `f3chal`：服务器挑战
- `f3resp`：客户端对挑战的响应

这样做的目的是使不同阶段的消息语义更清晰，并降低消息混淆的风险。

### 4. 加强最终响应绑定

原来的最终响应为：

```anb
{{f4(B, P, N_P_req, Photos)}inv(pk(B))}pk(P)
```

现在改为：

```anb
{{f4(B, P, N_P_req, N_B, Photos)}inv(pk(B))}pk(P)
```

也就是将 `B` 发出的 challenge `N_B` 也加入最终响应中。这样 `P` 不仅可以检查响应是否对应自己的请求 `N_P_req`，还可以检查响应是否属于当前 challenge-response 会话。

### 5. 增加 stronger authentication goals

原来只有一个 goal：

```anb
Photos secret between B,P
```

现在增加为：

```anb
Photos secret between B,P
P authenticates B on Photos,N_P_req,N_B
B authenticates P on N_P_req,N_B
```

新增的两个 goal 用来检查：

- `P` 接受的响应是否确实来自 `B`，并且绑定到当前请求和当前 challenge
- `B` 接受的请求是否确实来自一个真实的 `P` 会话，并且绑定到当前 challenge    

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
