package crypto

import (
	"bytes"
	"crypto/sha256"

	secp256k1 "github.com/btcsuite/btcd/btcec"
	. "github.com/neatio-net/common-go"
	"github.com/neatio-net/ed25519"
	"github.com/neatio-net/ed25519/extra25519"
	ethcrypto "github.com/neatio-net/neatio/utilities/crypto"
	"github.com/neatio-net/bls-go"
	"github.com/neatio-net/data-go"
	"github.com/neatio-net/wire-go"
	"golang.org/x/crypto/ripemd160"
)

type PubKey interface {
	Address() []byte
	Bytes() []byte
	KeyString() string
	VerifyBytes(msg []byte, sig Signature) bool
	Equals(PubKey) bool
}

var pubKeyMapper data.Mapper

func init() {
	pubKeyMapper = data.NewMapper(PubKeyS{}).
		RegisterImplementation(PubKeyEd25519{}, NameEd25519, TypeEd25519).
		RegisterImplementation(PubKeySecp256k1{}, NameSecp256k1, TypeSecp256k1).
		RegisterImplementation(EthereumPubKey{}, NameEthereum, TypeEthereum).
		RegisterImplementation(BLSPubKey{}, NameBls, TypeBls)
}

type PubKeyS struct {
	PubKey
}

func WrapPubKey(pk PubKey) PubKeyS {
	for ppk, ok := pk.(PubKeyS); ok; ppk, ok = pk.(PubKeyS) {
		pk = ppk.PubKey
	}
	return PubKeyS{pk}
}

func (p PubKeyS) MarshalJSON() ([]byte, error) {
	return pubKeyMapper.ToJSON(p.PubKey)
}

func (p *PubKeyS) UnmarshalJSON(data []byte) (err error) {
	parsed, err := pubKeyMapper.FromJSON(data)
	if err == nil && parsed != nil {
		p.PubKey = parsed.(PubKey)
	}
	return
}

func (p PubKeyS) Empty() bool {
	return p.PubKey == nil
}

func PubKeyFromBytes(pubKeyBytes []byte) (pubKey PubKey, err error) {
	err = wire.ReadBinaryBytes(pubKeyBytes, &pubKey)
	return
}

type PubKeyEd25519 [32]byte

func (pubKey PubKeyEd25519) Address() []byte {
	w, n, err := new(bytes.Buffer), new(int), new(error)
	wire.WriteBinary(pubKey[:], w, n, err)
	if *err != nil {
		PanicCrisis(*err)
	}
	encodedPubkey := append([]byte{TypeEd25519}, w.Bytes()...)
	hasher := ripemd160.New()
	hasher.Write(encodedPubkey)
	return hasher.Sum(nil)
}

func (pubKey PubKeyEd25519) Bytes() []byte {
	return wire.BinaryBytes(struct{ PubKey }{pubKey})
}

func (pubKey PubKeyEd25519) VerifyBytes(msg []byte, sig_ Signature) bool {
	if wrap, ok := sig_.(SignatureS); ok {
		sig_ = wrap.Signature
	}
	sig, ok := sig_.(SignatureEd25519)
	if !ok {
		return false
	}
	pubKeyBytes := [32]byte(pubKey)
	sigBytes := [64]byte(sig)
	return ed25519.Verify(&pubKeyBytes, msg, &sigBytes)
}

func (p PubKeyEd25519) MarshalJSON() ([]byte, error) {
	return data.Encoder.Marshal(p[:])
}

func (p *PubKeyEd25519) UnmarshalJSON(enc []byte) error {
	var ref []byte
	err := data.Encoder.Unmarshal(&ref, enc)
	copy(p[:], ref)
	return err
}

func (pubKey PubKeyEd25519) ToCurve25519() *[32]byte {
	keyCurve25519, pubKeyBytes := new([32]byte), [32]byte(pubKey)
	ok := extra25519.PublicKeyToCurve25519(keyCurve25519, &pubKeyBytes)
	if !ok {
		return nil
	}
	return keyCurve25519
}

func (pubKey PubKeyEd25519) String() string {
	return Fmt("PubKeyEd25519{%X}", pubKey[:])
}

func (pubKey PubKeyEd25519) KeyString() string {
	return Fmt("%X", pubKey[:])
}

func (pubKey PubKeyEd25519) Equals(other PubKey) bool {
	if otherEd, ok := other.(PubKeyEd25519); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	} else {
		return false
	}
}

type PubKeySecp256k1 [33]byte

func (pubKey PubKeySecp256k1) Address() []byte {
	hasherSHA256 := sha256.New()
	hasherSHA256.Write(pubKey[:])
	sha := hasherSHA256.Sum(nil)

	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha)
	return hasherRIPEMD160.Sum(nil)
}

func (pubKey PubKeySecp256k1) Bytes() []byte {
	return wire.BinaryBytes(struct{ PubKey }{pubKey})
}

func (pubKey PubKeySecp256k1) VerifyBytes(msg []byte, sig_ Signature) bool {
	if wrap, ok := sig_.(SignatureS); ok {
		sig_ = wrap.Signature
	}
	sig, ok := sig_.(SignatureSecp256k1)
	if !ok {
		return false
	}

	pub__, err := secp256k1.ParsePubKey(pubKey[:], secp256k1.S256())
	if err != nil {
		return false
	}
	sig__, err := secp256k1.ParseDERSignature(sig[:], secp256k1.S256())
	if err != nil {
		return false
	}
	return sig__.Verify(Sha256(msg), pub__)
}

func (p PubKeySecp256k1) MarshalJSON() ([]byte, error) {
	return data.Encoder.Marshal(p[:])
}

func (p *PubKeySecp256k1) UnmarshalJSON(enc []byte) error {
	var ref []byte
	err := data.Encoder.Unmarshal(&ref, enc)
	copy(p[:], ref)
	return err
}

func (pubKey PubKeySecp256k1) String() string {
	return Fmt("PubKeySecp256k1{%X}", pubKey[:])
}

func (pubKey PubKeySecp256k1) KeyString() string {
	return Fmt("%X", pubKey[:])
}

func (pubKey PubKeySecp256k1) Equals(other PubKey) bool {
	if otherSecp, ok := other.(PubKeySecp256k1); ok {
		return bytes.Equal(pubKey[:], otherSecp[:])
	} else {
		return false
	}
}

type EthereumPubKey []byte

func (pubKey EthereumPubKey) Address() []byte {
	cKey, _ := ethcrypto.UnmarshalPubkey(pubKey[:])
	address := ethcrypto.PubkeyToAddress(*cKey)
	return address[:]
}

func (pubKey EthereumPubKey) Bytes() []byte {
	return wire.BinaryBytes(struct{ PubKey }{pubKey})
}

func (pubKey EthereumPubKey) KeyString() string {
	return Fmt("EthPubKey{%X}", pubKey[:])
}

func (pubKey EthereumPubKey) VerifyBytes(msg []byte, sig_ Signature) bool {
	msg = ethcrypto.Keccak256(msg)
	recoveredPub, err := ethcrypto.Ecrecover(msg, sig_.(EthereumSignature).SigByte())
	if err != nil {
		return false
	}
	return bytes.Equal(pubKey[:], recoveredPub[:])
}

func (pubKey EthereumPubKey) Equals(other PubKey) bool {
	if otherEd, ok := other.(EthereumPubKey); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	} else {
		return false
	}
}

func (pubKey EthereumPubKey) MarshalJSON() ([]byte, error) {

	return data.Encoder.Marshal(pubKey[:])
}

func (p *EthereumPubKey) UnmarshalJSON(enc []byte) error {
	var ref []byte
	err := data.Encoder.Unmarshal(&ref, enc)
	copy((*p)[:], ref)
	return err
}

type BLSPubKey [128]byte

func (pubKey BLSPubKey) getElement() *bls.PublicKey {
	pb := &bls.PublicKey{}
	err := pb.Unmarshal(pubKey[:])
	if err != nil {
		return nil
	} else {
		return pb
	}
}

func (pubKey BLSPubKey) Bytes() []byte {
	return pubKey[:]
}

func BLSPubKeyAggregate(pks []*PubKey) *BLSPubKey {
	var _pks []*bls.PublicKey
	for _, pk := range pks {
		if _pk, ok := (*pk).(BLSPubKey); ok {
			_pks = append(_pks, _pk.getElement())
		} else {
			return nil
		}
	}

	var pub BLSPubKey
	copy(pub[:], new(bls.PublicKey).Aggregate(_pks...).Marshal())
	return &pub
}

func (pubKey BLSPubKey) Address() []byte {
	hasherSHA256 := sha256.New()
	hasherSHA256.Write(pubKey[:])
	sha := hasherSHA256.Sum(nil)

	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha)
	return hasherRIPEMD160.Sum(nil)
}

func (pubKey BLSPubKey) Equals(other PubKey) bool {
	if otherPk, ok := other.(BLSPubKey); ok {
		return pubKey == otherPk
	} else {
		return false
	}
}

func (pubKey BLSPubKey) VerifyBytes(msg []byte, sig_ Signature) bool {
	if otherSign, ok := sig_.(BLSSignature); ok {
		sign := otherSign.getElement()
		if sign == nil {
			return false
		}
		pub := pubKey.getElement()
		if pub == nil {
			return false
		}
		return bls.Verify(sign, msg, pub)
	} else {
		return false
	}
}

func (pubKey BLSPubKey) KeyString() string {
	return Fmt("0x%X", pubKey[:])
}

func (pubKey BLSPubKey) MarshalJSON() ([]byte, error) {
	return data.Encoder.Marshal(pubKey[:])
}

func (pubKey *BLSPubKey) UnmarshalJSON(enc []byte) error {
	var ref []byte
	err := data.Encoder.Unmarshal(&ref, enc)
	copy(pubKey[:], ref)
	return err
}
