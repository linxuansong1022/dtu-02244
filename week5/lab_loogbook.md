# Lab Logbook: Week 5 – Channel Abstraction

## Protocol Snapshot协议快照



------

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
