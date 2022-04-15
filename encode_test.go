package crypto

import (
	"strings"
	"testing"

	data "github.com/neatlib/data-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type byter interface {
	Bytes() []byte
}

func checkWire(t *testing.T, in byter, reader interface{}, typ byte) {

	bin, err := data.ToWire(in)
	require.Nil(t, err, "%+v", err)
	assert.Equal(t, typ, bin[0])

	assert.Equal(t, in.Bytes(), bin)

	err = data.FromWire(bin, reader)
	require.Nil(t, err, "%+v", err)
}

func checkJSON(t *testing.T, in interface{}, reader interface{}, typ string) {

	js, err := data.ToJSON(in)
	require.Nil(t, err, "%+v", err)
	styp := `"` + typ + `"`
	assert.True(t, strings.Contains(string(js), styp))

	err = data.FromJSON(js, reader)
	require.Nil(t, err, "%+v", err)

	text, err := data.ToText(in)
	require.Nil(t, err, "%+v", err)
	parts := strings.Split(text, ":")
	require.Equal(t, 2, len(parts))

	assert.Equal(t, typ, parts[0])

	assert.True(t, strings.Contains(string(js), parts[1]))
}

func TestKeyEncodings(t *testing.T) {
	cases := []struct {
		privKey PrivKeyS
		keyType byte
		keyName string
	}{
		{
			privKey: PrivKeyS{GenPrivKeyEd25519()},
			keyType: TypeEd25519,
			keyName: NameEd25519,
		},
		{
			privKey: PrivKeyS{GenPrivKeySecp256k1()},
			keyType: TypeSecp256k1,
			keyName: NameSecp256k1,
		},
	}

	for _, tc := range cases {

		priv2 := PrivKeyS{}
		checkWire(t, tc.privKey, &priv2, tc.keyType)
		assert.EqualValues(t, tc.privKey, priv2)
		priv3 := PrivKeyS{}
		checkJSON(t, tc.privKey, &priv3, tc.keyName)
		assert.EqualValues(t, tc.privKey, priv3)

		pubKey := PubKeyS{tc.privKey.PubKey()}
		pub2 := PubKeyS{}
		checkWire(t, pubKey, &pub2, tc.keyType)
		assert.EqualValues(t, pubKey, pub2)
		pub3 := PubKeyS{}
		checkJSON(t, pubKey, &pub3, tc.keyName)
		assert.EqualValues(t, pubKey, pub3)
	}
}

func toFromJSON(t *testing.T, in interface{}, recvr interface{}) {
	js, err := data.ToJSON(in)
	require.Nil(t, err, "%+v", err)
	err = data.FromJSON(js, recvr)
	require.Nil(t, err, "%+v", err)
}

func TestNilEncodings(t *testing.T) {

	a, b := SignatureS{}, SignatureS{}
	toFromJSON(t, a, &b)
	assert.EqualValues(t, a, b)

	c, d := PubKeyS{}, PubKeyS{}
	toFromJSON(t, c, &d)
	assert.EqualValues(t, c, d)

	e, f := PrivKeyS{}, PrivKeyS{}
	toFromJSON(t, e, &f)
	assert.EqualValues(t, e, f)

}
