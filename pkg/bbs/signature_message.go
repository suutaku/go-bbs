/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"github.com/suutaku/bls12381"
)

// SignatureMessage defines a message to be used for a signature check.
type SignatureMessage struct {
	FR *bls12381.Fr
}

// ParseSignatureMessage parses SignatureMessage from bytes.
func ParseSignatureMessage(message []byte) *SignatureMessage {
	elm := frFromOKM(message)

	return &SignatureMessage{
		FR: elm,
	}
}
