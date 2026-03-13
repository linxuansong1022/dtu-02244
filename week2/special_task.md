# Special Task: Static Analysis (Week 2)

## Task

Assume that the Week 2 protocol runs between honest agents `A`, `B`, and `P`, and that the intruder `i` is only a passive network observer. The intruder may read all traffic on the network, but does not block, modify, or inject messages.

The task is to determine what the intruder can learn from the network traffic under the standard Dolev-Yao analysis rules.

## Protocol Messages

According to [`week2_v1.AnB`](/Users/songlinxuan/Desktop/dtu02244/week2/week2_v1.AnB), the protocol messages are:

1. `M1: A -> P : {A, B, ReqA}inv(pk(A))`
2. `M2: P -> B : {A, P, ReqP}inv(pk(P))`
3. `M3: B -> A : {P, B, Token}inv(pk(B))`
4. `M4: A -> B : {P, B, Token}inv(pk(A))`
5. `M5: B -> P : {Photos}pk(P)`

The Week 2 model uses signatures for authentication and a public-key encryption in the final step to protect the photo data.

## Initial Intruder Knowledge

The passive intruder initially knows all public agent identities and public keys, together with its own key pair:

`K0 = {A, B, P, i, pk(A), pk(B), pk(P), pk(i), inv(pk(i))}`

In particular, the intruder does **not** know `inv(pk(P))`.

## Dolev-Yao Analysis

### 1. Signed Messages Can Be Opened

Messages `M1`, `M2`, `M3`, and `M4` are signed, not encrypted. By the Dolev-Yao `OpenSig` rule, the intruder can open signed messages and inspect their contents.

Therefore the intruder can read:

- from `M1`: `A`, `B`, `ReqA`
- from `M2`: `A`, `P`, `ReqP`
- from `M3`: `P`, `B`, `Token`
- from `M4`: `P`, `B`, `Token`

So after observing `M1` to `M4`, the intruder can derive the protocol metadata and the authorization token.

### 2. The Final Ciphertext Cannot Be Decrypted

Message `M5` is:

`{Photos}pk(P)`

To learn `Photos`, the intruder would need the private key `inv(pk(P))`. Since `inv(pk(P))` is not part of the initial intruder knowledge and is never sent on the network, the intruder cannot apply the Dolev-Yao decryption rule to this ciphertext.

Hence the intruder can observe the ciphertext itself, but cannot derive the plaintext `Photos`.

## Conclusion

Under passive observation, the intruder learns:

- the participating identities `A`, `B`, and `P`
- the request values `ReqA` and `ReqP`
- the token `Token`
- the existence of the final encrypted message to `P`

However, the intruder does **not** learn `Photos`.

Therefore, in the Week 2 protocol, the confidentiality goal for `Photos` is preserved against a passive Dolev-Yao intruder.

## Security Observation

Although `Photos` remains confidential under passive observation, the analysis already shows a structural weakness: the token is visible on the network because it is only signed, not encrypted. This does not break secrecy in the passive setting, but it suggests that the token may become useful to an active intruder in later attacks.
