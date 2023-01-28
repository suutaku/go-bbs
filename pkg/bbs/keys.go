/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/suutaku/bls12381"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
)

const (
	seedSize        = frCompressedSize
	generateKeySalt = "BBS-SIG-KEYGEN-SALT-"
)

// PublicKey defines BLS Public Key.
type PublicKey struct {
	PointG2 *bls12381.PointG2
}

// PrivateKey defines BLS Public Key.
type PrivateKey struct {
	FR *bls12381.Fr
}

// PublicKeyWithGenerators extends PublicKey with a blinding generator h0, a commitment to the secret key w,
// and a generator for each message h.
type PublicKeyWithGenerators struct {
	h0 *bls12381.PointG1
	h  []*bls12381.PointG1

	w *bls12381.PointG2

	messagesCount int
}

// ToPublicKeyWithGenerators creates PublicKeyWithGenerators from the PublicKey.
func (pk *PublicKey) ToPublicKeyWithGenerators(messagesCount int) (*PublicKeyWithGenerators, error) {
	offset := g2UncompressedSize + 1

	data := calcData(pk, messagesCount)

	h0, err := hashToG1(data)
	if err != nil {
		return nil, fmt.Errorf("create G1 point from hash")
	}

	h := make([]*bls12381.PointG1, messagesCount)

	for i := 1; i <= messagesCount; i++ {
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)

		iBytes := uint32ToBytes(uint32(i))

		for j := 0; j < len(iBytes); j++ {
			dataCopy[j+offset] = iBytes[j]
		}

		h[i-1], err = hashToG1(dataCopy)
		if err != nil {
			return nil, fmt.Errorf("create G1 point from hash: %w", err)
		}
	}

	return &PublicKeyWithGenerators{
		h0:            h0,
		h:             h,
		w:             pk.PointG2,
		messagesCount: messagesCount,
	}, nil
}

func calcData(key *PublicKey, messagesCount int) []byte {
	data := g2.ToUncompressed(key.PointG2)

	data = append(data, 0, 0, 0, 0, 0, 0)

	mcBytes := uint32ToBytes(uint32(messagesCount))

	data = append(data, mcBytes...)

	return data
}

func hashToG1(data []byte) (*bls12381.PointG1, error) {
	dstG1 := []byte("BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0")

	hashFunc := func() hash.Hash {
		// We pass a null key so error is impossible here.
		h, _ := blake2b.New512(nil) //nolint:errcheck
		return h
	}

	g := bls12381.NewG1()

	p, err := g.HashToCurveGeneric(data, dstG1, hashFunc)
	if err != nil {
		return nil, err
	}

	return g1.FromBytes(g.ToBytes(p))
}

// UnmarshalPrivateKey unmarshals PrivateKey.
func UnmarshalPrivateKey(privKeyBytes []byte) (*PrivateKey, error) {
	if len(privKeyBytes) != frCompressedSize {
		return nil, errors.New("invalid size of private key")
	}

	fr := parseFr(privKeyBytes)

	return &PrivateKey{
		FR: fr,
	}, nil
}

// Marshal marshals PrivateKey.
func (k *PrivateKey) Marshal() ([]byte, error) {
	bytes := k.FR.ToBytes()
	return bytes, nil
}

// PublicKey returns a Public Key as G2 point generated from the Private Key.
func (k *PrivateKey) PublicKey() *PublicKey {
	pointG2 := g2.One()
	g2.MulScalar(pointG2, pointG2, frToRepr(k.FR))

	return &PublicKey{pointG2}
}

// UnmarshalPublicKey parses a PublicKey from bytes.
func UnmarshalPublicKey(pubKeyBytes []byte) (*PublicKey, error) {
	if len(pubKeyBytes) != bls12381G2PublicKeyLen {
		return nil, errors.New("invalid size of public key")
	}

	pointG2, err := g2.FromCompressed(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize public key: %w", err)
	}

	return &PublicKey{
		PointG2: pointG2,
	}, nil
}

// Marshal marshals PublicKey.
func (pk *PublicKey) Marshal() ([]byte, error) {
	pkBytes := g2.ToCompressed(pk.PointG2)
	return pkBytes, nil
}

func (pk *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	if !ok {
		return ok
	}
	pkBytes := g2.ToCompressed(pk.PointG2)
	pkBytes2 := g2.ToCompressed(xx.PointG2)
	return bytes.Equal(pkBytes, pkBytes2)
}

// GenerateKeyPair generates BBS+ PublicKey and PrivateKey pair.
func GenerateKeyPair(h func() hash.Hash, seed []byte) (*PublicKey, *PrivateKey, error) {
	if len(seed) != 0 && len(seed) != seedSize {
		return nil, nil, errors.New("invalid size of seed")
	}

	okm, err := generateOKM(seed, h)
	if err != nil {
		return nil, nil, err
	}

	privKeyFr := frFromOKM(okm)

	privKey := &PrivateKey{privKeyFr}
	pubKey := privKey.PublicKey()

	return pubKey, privKey, nil
}

func generateOKM(ikm []byte, h func() hash.Hash) ([]byte, error) {
	salt := []byte(generateKeySalt)
	info := make([]byte, 2)

	if ikm != nil {
		ikm = append(ikm, 0)
	} else {
		ikm = make([]byte, seedSize+1)

		_, err := rand.Read(ikm)
		if err != nil {
			return nil, err
		}

		ikm[seedSize] = 0
	}

	return newHKDF(h, ikm, salt, info, frUncompressedSize)
}

func newHKDF(h func() hash.Hash, ikm, salt, info []byte, length int) ([]byte, error) {
	reader := hkdf.New(h, ikm, salt, info)
	result := make([]byte, length)

	_, err := io.ReadFull(reader, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

const (
	kty   = "EC"
	crvG1 = "BLS12381_G1"
	crvG2 = "BLS12381_G2"
)

type PublicKeyJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

func (pbk *PublicKey) ToJWK() *PublicKeyJWK {
	bs, err := pbk.Marshal()
	if err != nil {
		return nil
	}
	enc := base64.URLEncoding.EncodeToString(bs)
	return &PublicKeyJWK{
		Kty: kty,
		Crv: crvG2,
		X:   string(enc),
	}
}

func (jwk *PublicKeyJWK) ToPublicKey() *PublicKey {
	// check
	if jwk.Kty != kty {
		return nil
	}
	if jwk.Crv != crvG2 {
		return nil
	}
	bs, err := base64.URLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil
	}
	pt, err := g2.FromCompressed(bs)
	if err != nil {
		return nil
	}
	return &PublicKey{
		PointG2: pt,
	}
}
