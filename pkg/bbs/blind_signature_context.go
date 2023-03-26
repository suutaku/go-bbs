package bbs

import (
	"fmt"

	"github.com/suutaku/bls12381"
)

type BlindSignatureContext struct {
	commitment *bls12381.PointG1
	challenge  *bls12381.Fr
	proofs     *ProofG1
}

func NewBlindSignatureContext(msgs map[int][]byte, generators *PublicKeyWithGenerators, nonce *ProofNonce) (*BlindSignatureContext, *SignatureBliding, error) {

	blindFactory := NewSignatureBliding()
	builder := newCommitmentBuilder(len(msgs) + 1)

	// h0^blinding_factor*hi^mi.....
	builder.add(generators.h0, blindFactory.ToFr())

	committing := NewProverCommittingG1()
	committing.Commit(generators.h0)

	secrets := make([]*bls12381.Fr, 0)
	secrets = append(secrets, blindFactory.ToFr())

	for i := 0; i < generators.messagesCount; i++ {
		if _, contains := msgs[i]; contains {
			m := frFromOKM(msgs[i])
			secrets = append(secrets, m)
			builder.add(generators.h[i], m)
			committing.Commit(generators.h[i])
		}
	}

	// Create a random commitment, compute challenges and response.
	// The proof of knowledge consists of a commitment and responses
	// Prover and issuer engage in a proof of knowledge for `commitment`
	commitment := builder.build()
	committed := committing.Finish()

	extra := make([]byte, 0)
	extra = append(extra, g1.ToUncompressed(commitment)...)
	extra = append(extra, nonce.ToBytes()...)
	challenge := frFromOKM(extra)
	proofs := committed.GenerateProof(challenge, secrets)

	return &BlindSignatureContext{
		commitment: commitment,
		challenge:  challenge,
		proofs:     proofs,
	}, blindFactory, nil
}

func (bsc *BlindSignatureContext) MarshalJSON() ([]byte, error) {
	return bsc.ToBytes(), nil
}

func (bsc *BlindSignatureContext) UnmarshalJSON(input []byte) error {
	return bsc.FromBytes(input)
}

func (bsc *BlindSignatureContext) ToBytes() []byte {
	buffer := append(g1.ToCompressed(bsc.commitment), bsc.challenge.ToBytes()...)
	buffer = append(buffer, bsc.proofs.ToBytes()...)
	return buffer
}

func (bsc *BlindSignatureContext) FromBytes(input []byte) error {
	minSize := g1CompressedSize + 2*frCompressedSize + 4
	if len(input) < minSize {
		return fmt.Errorf("bad context size")
	}
	commitmentBytes := input[:g1CompressedSize]
	commiment, err := g1.FromCompressed(commitmentBytes)
	if err != nil {
		return err
	}
	bsc.commitment = commiment

	challengeBytes := input[g1CompressedSize : g1CompressedSize+frCompressedSize]
	challenge := bls12381.NewFr().FromBytes(challengeBytes)
	if challenge == nil {
		return fmt.Errorf("cannot parse challenge")
	}
	bsc.challenge = challenge

	proofBytes := input[g1CompressedSize+frCompressedSize:]
	bsc.proofs, err = ParseProofG1(proofBytes)
	return err
}

func (bsc *BlindSignatureContext) Verify(revealedMsg map[int]*SignatureMessage, generators *PublicKeyWithGenerators, nonce *ProofNonce) error {
	bases := make([]*bls12381.PointG1, 0)
	bases = append(bases, generators.h0)

	for i := 0; i < generators.messagesCount; i++ {
		if _, contains := revealedMsg[i]; !contains {
			bases = append(bases, generators.h[i])
		}
	}

	commitment := bsc.proofs.getChallengeContribution(
		bases,
		bsc.commitment,
		bsc.challenge)

	challengeBytes := make([]byte, 0)
	challengeBytes = append(challengeBytes, g1.ToUncompressed(bsc.commitment)...)
	challengeBytes = append(challengeBytes, nonce.ToBytes()...)
	challenge := frFromOKM(challengeBytes)
	challenge.Sub(challenge, bsc.challenge)
	g1.Sub(commitment, commitment, bsc.proofs.commitment)
	if g1.IsZero(commitment) && challenge.IsZero() {
		return nil
	}
	return fmt.Errorf("invlaid proof")
}

func (bsc *BlindSignatureContext) ToBlindSignature(msgs map[int][]byte, privKey *PrivateKey, generators *PublicKeyWithGenerators, nonce *ProofNonce) (*BlindSignature, error) {
	if msgs == nil {
		return nil, fmt.Errorf("messages was empty")
	}
	if privKey == nil {
		return nil, fmt.Errorf("private key was empty")
	}

	messagesFr := make(map[int]*SignatureMessage, 0)

	for i := 0; i < generators.messagesCount; i++ {
		if _, contains := msgs[i]; contains {
			messagesFr[i] = ParseSignatureMessage(msgs[i])
		}
	}
	err := bsc.Verify(messagesFr, generators, nonce)
	if err != nil {
		return nil, err
	}
	return NewBlindSignature(bsc.commitment, messagesFr, privKey, generators), nil
}
