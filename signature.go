package crypto

import (
	"bytes"
	"fmt"

	"encoding/hex"
	"encoding/json"

	. "github.com/neatio-network/common-go"
	"github.com/neatlib/bls-go"
	"github.com/neatlib/data-go"
	"github.com/neatlib/wire-go"
)

type Signature interface {
	Bytes() []byte
	IsZero() bool
	String() string
	Equals(Signature) bool
}

var sigMapper data.Mapper

func init() {
	sigMapper = data.NewMapper(SignatureS{}).
		RegisterImplementation(SignatureEd25519{}, NameEd25519, TypeEd25519).
		RegisterImplementation(SignatureSecp256k1{}, NameSecp256k1, TypeSecp256k1).
		RegisterImplementation(EthereumSignature{}, NameEthereum, TypeEthereum).
		RegisterImplementation(BLSSignature{}, NameBls, TypeBls)
}

type SignatureS struct {
	Signature
}

func WrapSignature(sig Signature) SignatureS {
	for ssig, ok := sig.(SignatureS); ok; ssig, ok = sig.(SignatureS) {
		sig = ssig.Signature
	}
	return SignatureS{sig}
}

func (p SignatureS) MarshalJSON() ([]byte, error) {
	return sigMapper.ToJSON(p.Signature)
}

func (p *SignatureS) UnmarshalJSON(data []byte) (err error) {
	parsed, err := sigMapper.FromJSON(data)
	if err == nil && parsed != nil {
		p.Signature = parsed.(Signature)
	}
	return
}

func (p SignatureS) Empty() bool {
	return p.Signature == nil
}

func SignatureFromBytes(sigBytes []byte) (sig Signature, err error) {
	err = wire.ReadBinaryBytes(sigBytes, &sig)
	return
}

type SignatureEd25519 [64]byte

func (sig SignatureEd25519) Bytes() []byte {
	return wire.BinaryBytes(struct{ Signature }{sig})
}

func (sig SignatureEd25519) IsZero() bool { return len(sig) == 0 }

func (sig SignatureEd25519) String() string { return fmt.Sprintf("/%X.../", Fingerprint(sig[:])) }

func (sig SignatureEd25519) Equals(other Signature) bool {
	if otherEd, ok := other.(SignatureEd25519); ok {
		return bytes.Equal(sig[:], otherEd[:])
	} else {
		return false
	}
}

func (p SignatureEd25519) MarshalJSON() ([]byte, error) {
	return data.Encoder.Marshal(p[:])
}

func (p *SignatureEd25519) UnmarshalJSON(enc []byte) error {
	var ref []byte
	err := data.Encoder.Unmarshal(&ref, enc)
	copy(p[:], ref)
	return err
}

type SignatureSecp256k1 []byte

func (sig SignatureSecp256k1) Bytes() []byte {
	return wire.BinaryBytes(struct{ Signature }{sig})
}

func (sig SignatureSecp256k1) IsZero() bool { return len(sig) == 0 }

func (sig SignatureSecp256k1) String() string { return fmt.Sprintf("/%X.../", Fingerprint(sig[:])) }

func (sig SignatureSecp256k1) Equals(other Signature) bool {
	if otherEd, ok := other.(SignatureSecp256k1); ok {
		return bytes.Equal(sig[:], otherEd[:])
	} else {
		return false
	}
}
func (p SignatureSecp256k1) MarshalJSON() ([]byte, error) {
	return data.Encoder.Marshal(p)
}

func (p *SignatureSecp256k1) UnmarshalJSON(enc []byte) error {
	return data.Encoder.Unmarshal((*[]byte)(p), enc)
}

type EthereumSignature []byte

func (sig EthereumSignature) SigByte() []byte {
	return sig[:]
}

func (sig EthereumSignature) Bytes() []byte {
	return wire.BinaryBytes(struct{ Signature }{sig})
}

func (sig EthereumSignature) IsZero() bool {
	return len(sig) == 0
}

func (sig EthereumSignature) String() string {
	return fmt.Sprintf("/%X.../", Fingerprint(sig[:]))
}

func (sig EthereumSignature) Equals(other Signature) bool {

	if otherEd, ok := other.(EthereumSignature); ok {
		return bytes.Equal(sig[:], otherEd[:])
	} else {
		return false
	}
}

func (sig EthereumSignature) MarshalJSON() ([]byte, error) {
	return data.Encoder.Marshal(sig[:])
}

func (sig *EthereumSignature) UnmarshalJSON(enc []byte) error {
	var ref []byte
	err := data.Encoder.Unmarshal(&ref, enc)
	*sig = make(EthereumSignature, len(ref))
	copy((*sig)[:], ref)
	return err
}

type BLSSignature []byte

func BLSSignatureAggregate(sigs []*Signature) BLSSignature {
	var _sigs []*bls.Signature
	for _, sig := range sigs {
		if _sig, ok := (*sig).(BLSSignature); ok {
			_sigs = append(_sigs, _sig.getElement())
		} else {
			return nil
		}
	}
	return new(bls.Signature).Aggregate(_sigs...).Marshal()
}

func (sig BLSSignature) getElement() *bls.Signature {
	sign := &bls.Signature{}
	err := sign.Unmarshal(sig)
	if err != nil {
		return nil
	} else {
		return sign
	}
}

func (sig BLSSignature) IsZero() bool { return len(sig) == 0 }

func (sig BLSSignature) Bytes() []byte {
	return sig
}

func (sig BLSSignature) String() string { return fmt.Sprintf("/%X.../", Fingerprint(sig)) }

func (sig BLSSignature) Equals(other Signature) bool {
	if otherSig, ok := (other).(BLSSignature); ok {
		return bytes.Equal(sig, otherSig)
	} else {
		return false
	}
}

func (p BLSSignature) MarshalJSON() ([]byte, error) {
	s := "0x" + hex.EncodeToString(p)
	return json.Marshal(s)
}

func (p *BLSSignature) UnmarshalJSON(enc []byte) error {
	var ref []byte
	err := data.Encoder.Unmarshal(&ref, enc)
	copy(*p, ref)
	return err
}
