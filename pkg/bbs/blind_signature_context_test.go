package bbs

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlindSignatureContext(t *testing.T) {
	privBytes, _ := hex.DecodeString("4b47459199b0c2210de9d28c1412551c28c57caae60872aa677bc9af2038d22b")
	pubBytes, _ := hex.DecodeString("ac4fd7ede2ba8a253f9ca8b8c8015334045252e2cd7290fa52fcb91ebebac64309e20823c03d0e3672a16fa783d614050485729c5aeee9d3000853657a2c691933113377843069e419e9a90886aa244e363c42ed342e9b7bd360b874dc9fd738")
	nonce := []byte("nonce")
	priv, err := UnmarshalPrivateKey(privBytes)
	require.NoError(t, err)
	pub, err := UnmarshalPublicKey([]byte(pubBytes))
	require.NoError(t, err)

	// messages := [][]byte{
	// 	[]byte("identity"),
	// 	[]byte("name"),
	// 	[]byte("gender"),
	// 	[]byte("phone number"),
	// 	[]byte("address"),
	// }

	generators, err := pub.ToPublicKeyWithGenerators(5)
	require.NoError(t, err)

	// holder pre blind secret
	secretMsgs := make(map[int][]byte, 0)
	secretMsgs[0] = []byte("identity")
	secretMsgs[2] = []byte("password")
	secretMsgs[4] = []byte("phone number")

	ctx, blinding, err := NewBlindSignatureContext(secretMsgs, generators, nonce)
	require.NoError(t, err)
	require.NotNil(t, blinding)
	require.False(t, blinding.IsZero())
	require.NotNil(t, ctx)
	require.False(t, ctx.challenge.IsZero())

	// marshal/unmarshal test
	ctxBytes := ctx.ToBytes()
	require.NotNil(t, ctxBytes)
	nctx := new(BlindSignatureContext)
	err = nctx.FromBytes(ctxBytes)
	require.NoError(t, err)
	require.True(t, ctx.challenge.Equal(nctx.challenge))
	require.True(t, g1.Equal(ctx.commitment, nctx.commitment))
	require.True(t, g1.Equal(ctx.proofs.commitment, nctx.proofs.commitment))
	for i, v := range ctx.proofs.responses {
		require.True(t, v.Equal(nctx.proofs.responses[i]))
	}

	// signer use known message with index to create blinding signature
	revealedMsg := make(map[int][]byte, 0)
	revealedMsg[1] = []byte("firstname")
	revealedMsg[3] = []byte("age")

	blindSig, err := ctx.ToBlindSignature(revealedMsg, priv, generators, nonce)
	require.NoError(t, err)
	require.NotNil(t, blindSig)

	// holder convert blinding signature to signature
	sig := blindSig.ToUnblinded((*SignatureBliding)(blinding))
	require.NotNil(t, sig)

	// verifier verify signature
	allMsg := make([]*SignatureMessage, 5)
	allMsg[0] = ParseSignatureMessage([]byte("identity"))
	allMsg[1] = ParseSignatureMessage([]byte("firstname"))
	allMsg[2] = ParseSignatureMessage([]byte("password"))
	allMsg[3] = ParseSignatureMessage([]byte("age"))
	allMsg[4] = ParseSignatureMessage([]byte("phone number"))

	err = sig.Verify(allMsg, generators)
	require.NoError(t, err)
}
