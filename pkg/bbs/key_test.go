package bbs

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKey(t *testing.T) {
	pub, priv, err := GenerateKeyPair(sha256.New, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, pub)
	assert.NotEmpty(t, priv)

	// publicKey to JWK
	jwk := pub.ToJWK()
	assert.NotEmpty(t, jwk)
	newPub := jwk.ToPublicKey()
	assert.NotEmpty(t, newPub)
	assert.Equal(t, newPub, pub)
}
