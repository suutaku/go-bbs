package bbs

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

var signature []byte
var pubkeyBytes []byte
var message = []byte("hello,john")
var err error

func TestSign(t *testing.T) {
	_, priv, _ := GenerateKeyPair(sha256.New, nil)
	bbsins := NewBbs()

	signature, err = bbsins.SignWithKey([][]byte{message}, priv)
	require.NoError(t, err)
	pubkeyBytes, err = priv.PublicKey().Marshal()
	require.NoError(t, err)
}

func TestVerify(t *testing.T) {
	bbsins := NewBbs()
	err = bbsins.Verify([][]byte{message}, signature, pubkeyBytes)
	require.NoError(t, err)
	invalidMessage := append(message, byte('!'))
	err = bbsins.Verify([][]byte{invalidMessage}, signature, pubkeyBytes)
	require.Error(t, err)
	invalidSignature := append(signature, byte('!'))
	err = bbsins.Verify([][]byte{invalidMessage}, invalidSignature, pubkeyBytes)
	require.Error(t, err)
	invalidPubkey := append(pubkeyBytes, byte('!'))
	err = bbsins.Verify([][]byte{invalidMessage}, invalidSignature, invalidPubkey)
	require.Error(t, err)
}
