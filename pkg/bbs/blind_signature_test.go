package bbs

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlindSign(t *testing.T) {
	pub, priv, err := GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)
	generators, err := pub.ToPublicKeyWithGenerators(5)
	require.NoError(t, err)
	blindFactory := NewSignatureBliding()

	msg := ParseSignatureMessage([]byte("message_0"))

	builder := newCommitmentBuilder(0)
	builder.add(generators.h0, blindFactory.ToFr())
	builder.add(generators.h[0], msg.FR)

	commitment := builder.build()

	reveMsg := map[int]*SignatureMessage{
		1: ParseSignatureMessage([]byte("message_1")),
		2: ParseSignatureMessage([]byte("message_2")),
		3: ParseSignatureMessage([]byte("message_3")),
		4: ParseSignatureMessage([]byte("message_4")),
	}

	blindSig := NewBlindSignature(commitment, reveMsg, priv, generators)
	require.NotNil(t, blindSig)
	sig := blindSig.ToUnblinded(blindFactory)
	require.NotNil(t, sig)
	reveMsg[0] = msg
	allMsgs := []*SignatureMessage{
		ParseSignatureMessage([]byte("message_0")),
		ParseSignatureMessage([]byte("message_1")),
		ParseSignatureMessage([]byte("message_2")),
		ParseSignatureMessage([]byte("message_3")),
		ParseSignatureMessage([]byte("message_4")),
	}
	err = sig.Verify(allMsgs, generators)
	require.NoError(t, err)
}

func TestMarshalAndUnmarshal(t *testing.T) {
	pub, priv, err := GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)
	generators, err := pub.ToPublicKeyWithGenerators(5)
	require.NoError(t, err)
	blindFactory := NewSignatureBliding()

	msg := ParseSignatureMessage([]byte("message_0"))

	builder := newCommitmentBuilder(0)
	builder.add(generators.h0, blindFactory.ToFr())
	builder.add(generators.h[0], msg.FR)

	commitment := builder.build()

	reveMsg := map[int]*SignatureMessage{
		1: ParseSignatureMessage([]byte("message_1")),
		2: ParseSignatureMessage([]byte("message_2")),
		3: ParseSignatureMessage([]byte("message_3")),
		4: ParseSignatureMessage([]byte("message_4")),
	}

	blindSig := NewBlindSignature(commitment, reveMsg, priv, generators)
	require.NotNil(t, blindSig)

	jsonBs, err := json.Marshal(blindSig)
	require.NoError(t, err)
	blidSig2 := &BlindSignature{}
	err = json.Unmarshal(jsonBs, blidSig2)
	require.NoError(t, err)

}
