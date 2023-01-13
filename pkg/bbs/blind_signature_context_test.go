package bbs

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlindSignatureContext(t *testing.T) {
	issuerPrivateKeyBytes, err := hex.DecodeString("4b47459199b0c2210de9d28c1412551c28c57caae60872aa677bc9af2038d22b")
	require.NoError(t, err)

	issuerPrivateKey, err := UnmarshalPrivateKey(issuerPrivateKeyBytes)
	require.NoError(t, err)

	issuerGenerators, err := issuerPrivateKey.PublicKey().ToPublicKeyWithGenerators(25)
	require.NoError(t, err)

	nonce := NewProofNonce()

	// holder pre blind secret
	secretMsgs := make(map[int][]byte, 0)
	secretMsgs[17] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/identifier> "83627465" .`)

	ctx, blinding, err := NewBlindSignatureContext(secretMsgs, issuerGenerators, nonce)
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
	revealedMsg[0] = []byte(`_:c14n0 <http://purl.org/dc/terms/created> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`)
	revealedMsg[1] = []byte(`_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .`)
	revealedMsg[2] = []byte(`_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .`)
	revealedMsg[3] = []byte(`_:c14n0 <https://w3id.org/security#verificationMethod> <did:example:123456#key1> .`)
	revealedMsg[4] = []byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/birthDate> "1958-07-17"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`)
	revealedMsg[5] = []byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/familyName> "SMITH" .`)
	revealedMsg[6] = []byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/gender> "Male" .`)
	revealedMsg[7] = []byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/givenName> "JOHN" .`)
	revealedMsg[8] = []byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/image> <data:image/png;base64,iVBORw0KGgokJggg==> .`)
	revealedMsg[9] = []byte(`<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .`)
	revealedMsg[10] = []byte(`<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .`)
	revealedMsg[11] = []byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#birthCountry> "Bahamas" .`)
	revealedMsg[12] = []byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#commuterClassification> "C1" .`)
	revealedMsg[13] = []byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprCategory> "C09" .`)
	revealedMsg[14] = []byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprNumber> "999-999-999" .`)
	revealedMsg[15] = []byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`)
	revealedMsg[16] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/description> "Government of Example Permanent Resident Card." .`)
	revealedMsg[18] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .`)
	revealedMsg[19] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .`)
	revealedMsg[20] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .`)
	revealedMsg[21] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:b34ca6cd37bbf23> .`)
	revealedMsg[22] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`)
	revealedMsg[23] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`)
	revealedMsg[24] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:example:489398593> .`)

	blindSig, err := ctx.ToBlindSignature(revealedMsg, issuerPrivateKey, issuerGenerators, nonce)
	require.NoError(t, err)
	require.NotNil(t, blindSig)

	// holder convert blinding signature to signature
	sig := blindSig.ToUnblinded((*SignatureBliding)(blinding))
	require.NotNil(t, sig)

	// verifier verify signature
	allMsg := make([]*SignatureMessage, 25)
	// allMsg[0] = ParseSignatureMessage([]byte("identity"))
	// allMsg[1] = ParseSignatureMessage([]byte("firstname"))
	// allMsg[2] = ParseSignatureMessage([]byte("password"))
	// allMsg[3] = ParseSignatureMessage([]byte("age"))
	// allMsg[4] = ParseSignatureMessage([]byte("phone number"))
	allMsg[0] = ParseSignatureMessage([]byte(`_:c14n0 <http://purl.org/dc/terms/created> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`))
	allMsg[1] = ParseSignatureMessage([]byte(`_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .`))
	allMsg[2] = ParseSignatureMessage([]byte(`_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .`))
	allMsg[3] = ParseSignatureMessage([]byte(`_:c14n0 <https://w3id.org/security#verificationMethod> <did:example:123456#key1> .`))
	allMsg[4] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/birthDate> "1958-07-17"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`))
	allMsg[5] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/familyName> "SMITH" .`))
	allMsg[6] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/gender> "Male" .`))
	allMsg[7] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/givenName> "JOHN" .`))
	allMsg[8] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/image> <data:image/png;base64,iVBORw0KGgokJggg==> .`))
	allMsg[9] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .`))
	allMsg[10] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .`))
	allMsg[11] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#birthCountry> "Bahamas" .`))
	allMsg[12] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#commuterClassification> "C1" .`))
	allMsg[13] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprCategory> "C09" .`))
	allMsg[14] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprNumber> "999-999-999" .`))
	allMsg[15] = ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`))
	allMsg[16] = ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/description> "Government of Example Permanent Resident Card." .`))
	allMsg[17] = ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/identifier> "83627465" .`))
	allMsg[18] = ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .`))
	allMsg[19] = ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .`))
	allMsg[20] = ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .`))
	allMsg[21] = ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:b34ca6cd37bbf23> .`))
	allMsg[22] = ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`))
	allMsg[23] = ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`))
	allMsg[24] = ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:example:489398593> .`))

	err = sig.Verify(allMsg, issuerGenerators)
	require.NoError(t, err)
}
