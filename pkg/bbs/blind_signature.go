package bbs

import (
	"errors"
	"fmt"

	"github.com/suutaku/bls12381"
)

type SignatureBliding bls12381.Fr

type BlindSignature struct {
	A *bls12381.PointG1
	E *bls12381.Fr
	S *bls12381.Fr
}

func NewBlindSignature(commiment *bls12381.PointG1, msgs map[int]*SignatureMessage, priv *PrivateKey, generotors *PublicKeyWithGenerators) *BlindSignature {
	scalars := make([]*bls12381.Fr, 0)
	points := make([]*bls12381.PointG1, 0)
	e := createRandSignatureFr()
	s := createRandSignatureFr()
	points = append(points, commiment)
	scalars = append(scalars, frToRepr(bls12381.NewFr().One()))
	points = append(points, g1.One())
	scalars = append(scalars, frToRepr(bls12381.NewFr().One()))
	points = append(points, generotors.h0)
	scalars = append(scalars, s)

	for i, m := range msgs {
		scalars = append(scalars, m.FR)
		points = append(points, generotors.h[i])
	}

	b := sumOfG1Products(points, scalars)
	exp := bls12381.NewFr()
	exp.Set(priv.FR)
	exp.Add(exp, e)
	expInver := bls12381.NewFr()
	expInver.Inverse(exp)
	g1.MulScalar(b, b, expInver)
	return &BlindSignature{
		A: b,
		E: e,
		S: s,
	}
}

func ParseBlindSignature(sigBytes []byte) (*BlindSignature, error) {
	if len(sigBytes) != bls12381SignatureLen {
		return nil, errors.New("invalid size of signature")
	}

	pointG1, err := g1.FromCompressed(sigBytes[:g1CompressedSize])
	if err != nil {
		return nil, fmt.Errorf("deserialize G1 compressed signature: %w", err)
	}

	e := parseFr(sigBytes[g1CompressedSize : g1CompressedSize+frCompressedSize])
	s := parseFr(sigBytes[g1CompressedSize+frCompressedSize:])

	return &BlindSignature{
		A: pointG1,
		E: e,
		S: s,
	}, nil
}

// ToBytes converts signature to bytes using compression of G1 point and E, S FR points.
func (bs *BlindSignature) ToBytes() ([]byte, error) {
	bytes := make([]byte, bls12381SignatureLen)

	copy(bytes, g1.ToCompressed(bs.A))
	copy(bytes[g1CompressedSize:g1CompressedSize+frCompressedSize], bs.E.ToBytes())
	copy(bytes[g1CompressedSize+frCompressedSize:], bs.S.ToBytes())

	return bytes, nil
}

func (bs *BlindSignature) ToUnblinded(blinder *SignatureBliding) *Signature {
	ret := &Signature{
		A: bs.A,
		E: bs.E,
		S: bls12381.NewFr(),
	}
	ret.S.Add(bs.S, (*bls12381.Fr)(blinder))
	return ret
}
