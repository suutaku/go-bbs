# go-bbs
[![Go Report Card](https://goreportcard.com/badge/github.com/suutaku/go-bbs)](https://goreportcard.com/report/github.com/suutaku/go-bbs)
[![GitHub release](https://img.shields.io/github/release/suutaku/go-bbs?include_prereleases=&sort=semver&color=blue)](https://github.com/suutaku/go-bbs/releases/)
[![License](https://img.shields.io/badge/License-MIT-blue)](#license)
[![dependency - github.com/suutaku/bls12381](https://img.shields.io/badge/dependency-github.com%2Fsuutaku%2Fbls12381-blue)](https://pkg.go.dev/github.com/suutaku/bls12381)
 A **BBS++** signature pure go implementation refer to [hyperledger/ursa](https://github.com/hyperledger/ursa.git) (**Rust**) and [heyperledger/aries-framework-go](https://github.com/hyperledger/aries-framework-go.git) (**Without Blind sign**).
 

## Keygen

BBS+ supports two types of public keys. One that is created as described in the paper where the message specific generators
are randomly generated
and a deterministic version that looks like a BLS public key and whose message specific generators are computed using
IETF's [Hash to Curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1) algorithm which is also constant time combined with known inputs.

```golang
  pub, priv, err := bbs.GenerateKeyPair(sha256.New, nil)
  if err != nil {
    panic(err)
  }
```

## Signing

Signing can be done where the signer knows all the messages or where the signature recipient commits to some messages beforehand
and the signer completes the signature with the remaining messages.

To create a signature:

```golang
_, priv, _ := bbs.GenerateKeyPair(sha256.New, nil)
bbsInstance := bbs.NewBbs()

signature, err := bbsInstance.SignWithKey([][]byte{message}, priv)
require.NoError(t, err)

```

## Blinding Signing

Blinding signing needs **Issuer** and **Holder** exchange `Nonce` and `BlindSignatureContext`.

**Step 1.** **Issuer** create a `Nonce` and send to **Holder**

**Step 2.** **Holder** recived `Nonce`,  use it to create a `BlindSignatureContext` and a `BlindingFactory`. Keep `BlindingFactory` and send `BlindSignatureContext`  to **Issuer**.

```golang
// holder pre blind secret
secretMsgs := make(map[int][]byte, 0)
secretMsgs[0] = []byte("identity")
secretMsgs[2] = []byte("password")
secretMsgs[4] = []byte("phone number")

ctx, blinding, err := NewBlindSignatureContext(secretMsgs, generators, nonce)
require.NoError(t, err)
```
Note: `generator` can generated from **Holder**'s PublicKey, the `messageCount` is sum of all messages (secret message number + revealed message number):

```golang
generators, err := pub.ToPublicKeyWithGenerators(messageCount)
require.NoError(t, err)
```

**Step 3.** **Issuer** recived `BlindSignatureContext` and revealed messages, verify secret commitment in `BlindSignatureContext` and create a **Blind Signature**.

```golang
// signer use known message with index to create blinding signature
revealedMsg := make(map[int][]byte, 0)
revealedMsg[1] = []byte("firstname")
revealedMsg[3] = []byte("age")

blindSig, err := ctx.ToBlindSignature(revealedMsg, priv, generators, nonce)
require.NoError(t, err)
require.NotNil(t, blindSig)
```

**Step 4.** **Holder** recived `blind signature`, convert it to `signature` with `blindingFactory`:

```golang
// holder convert blinding signature to signature
sig := blindSig.ToUnblinded((*SignatureBliding)(blinding))
require.NotNil(t, sig)
```

**Step 5.** Finally, **Holder** can verify signature with all Messages:

```golang
// verifier verify signature
allMsg := make([]*SignatureMessage, 5)
allMsg[0] = ParseSignatureMessage([]byte("identity"))
allMsg[1] = ParseSignatureMessage([]byte("firstname"))
allMsg[2] = ParseSignatureMessage([]byte("password"))
allMsg[3] = ParseSignatureMessage([]byte("age"))
allMsg[4] = ParseSignatureMessage([]byte("phone number"))

err = sig.Verify(allMsg, generators)
require.NoError(t, err)
```

At this time, blinding signature is end and some secret message was not known to **Issuer**.
Now you can use `signature` to create `SelectiveDisclosure` with `DeriveProof`.

## DeriveProof
DeriveProof derives a proof of BBS+ signature with some messages disclosed.

```golang
allMsg := make([]*SignatureMessage, 5)
allMsg[0] = ParseSignatureMessage([]byte("identity"))
allMsg[1] = ParseSignatureMessage([]byte("firstname"))
allMsg[2] = ParseSignatureMessage([]byte("password"))
allMsg[3] = ParseSignatureMessage([]byte("age"))
allMsg[4] = ParseSignatureMessage([]byte("phone number"))

revealedIndexes := []int{
  1,3,4,
}

proof,err := bbsInstance.DeriveProof(allMsg, signature, nonce, pubkey, revealedIndexes)

```

## Verify Proof
VerifyProof verifies BBS+ signature proof for one or more revealed messages.

```golang
 err := bbsInstance.VerifyProof(messagesBytes, proof, nonce, pubKeyBytes) 
```

## License

Released under [MIT](/LICENSE) by [@suutaku](https://github.com/suutaku).




