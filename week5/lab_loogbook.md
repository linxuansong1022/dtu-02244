# Lab Logbook: Week 5 – Channel Abstraction

## Protocol Snapshot协议快照

### 主协议
```AnB
Protocol: OpenAuth_v5_TLSChannels

Types:
  Agent A,B,P,IdP;
  Number ReqA,Photos,N_A,N_P_req;
  Function pk,pw;
  Format f1,f2,f3,f4;

Knowledge:
  A: A,B,P,IdP,pk(IdP),pw(A);
  B: A,B,P,IdP,pk(B),pk(P),pk(IdP),inv(pk(B));
  P: A,B,P,IdP,pk(B),pk(P),pk(IdP),inv(pk(P));
  IdP: A,B,P,IdP,pk(B),pk(P),pk(IdP),inv(pk(IdP)),pw(A);

Actions:

  [A] *->* IdP: f1(A,B,P,ReqA,N_A,pw(A))
  IdP *->* [A]: {f2(A,B,P,ReqA,N_A)}inv(pk(IdP))
  [A] *->* P: {f2(A,B,P,ReqA,N_A)}inv(pk(IdP))
  [P] *->* B: f3({f2(A,B,P,ReqA,N_A)}inv(pk(IdP)),N_P_req)
  B *->* [P]: f4(Photos)

Goals:
  Photos secret between B,P
```

### 子协议
```AnB
Protocol: KeyLookup_v5_TLSChannels

Types:
  Agent A,X,IdP;
  Number N_A;
  Function pk;
  Format f1,f2;

Knowledge:
  A: A,X,IdP,pk(IdP);
  IdP: IdP,A,X,pk(IdP),inv(pk(IdP)),pk(X);

Actions:

  [A] *->* IdP: f1(A,X,N_A)
  IdP *->* [A]: f2(A,X,pk(X),N_A)

Goals:
  A authenticates IdP on pk(X),N_A
```


## Changes from Week 4

Key modification: Replacement of transport-layer cryptography by pseudonymous TLS channels (`[X] *->* Y`).

关键修改：用伪匿名 TLS 通道替换传输层加密（ `[X] *->* Y` ）。

All communications between:所有通信内容如下：

- A and IdP
- A and P
- P and B

are now modeled as TLS channels with server-side authentication only.现在被建模为仅具有服务器端身份验证的 TLS 通道。

The authorization token issued by the Identity Provider remains signed using `inv(pk(IdP))`.身份提供商颁发的授权令牌仍然使用 `inv(pk(IdP))` 进行签名。

, since this signature represents a semantic authorization statement rather than merely transport protection. TLS alone would not allow P or B to verify that the token was genuinely issued by the Identity Provider.因为该签名代表的是语义授权声明，而不仅仅是传输保护。仅靠 TLS 无法让 P 或 B 验证令牌是否确实由身份提供商签发。

------

## Modeling considerations建模考虑因素

- TLS channels are modeled as secure pseudonymous channels (`*->*`).TLS 通道被建模为安全的假名通道（ `*->*` ）。
- Server authentication is guaranteed, but client identity is not established at the channel level.服务器身份验证得到保证，但客户端身份无法在通道级别建立。

Security goals remain unchanged:安全目标保持不变：

- `Photos secret between B,P`
- Authentication goals in the sub-protocol 子协议中的身份验证目标。

------

## Problems encountered遇到的问题

- The pseudonymous channel model abstracts away low-level crypto details, making it necessary to reason more carefully about which signatures must remain at the application layer.匿名通道模型抽象掉了底层加密细节，因此需要更仔细地考虑哪些签名必须保留在应用层。
