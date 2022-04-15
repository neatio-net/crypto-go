package crypto

import (
	"errors"

	"github.com/neatlab/neatio/utilities/common"
)

func CheckConsensusPubKey(from common.Address, consensusPubkey, signature []byte) error {
	if len(consensusPubkey) != 128 {
		return errors.New("invalid consensus public key")
	}

	if len(signature) != 64 {
		return errors.New("invalid signature")
	}

	var blsPK BLSPubKey
	copy(blsPK[:], consensusPubkey)

	blsSign := BLSSignature(signature)

	success := blsPK.VerifyBytes(from.Bytes(), blsSign)
	if !success {
		return errors.New("consensus public key signature verification failed")
	}
	return nil
}
