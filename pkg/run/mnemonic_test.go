package run

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/types"
)

func TestRecoveryMnemonic(t *testing.T) {
	expectedAddr := "NYVHOQARUV4JCCKN55C3WJB6GBE5KL3OOGILRQLLGOJXCMAQJCWT77N2JQ"
	key, err := hex.DecodeString("12365e9556e40eafa95ad338bc0a8fa73fcd700beeee68ce9f28c7fb614cd96d")
	if err != nil {
		t.Fatal(err)
	}
	m, err := mnemonic.FromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := mnemonic.ToPrivateKey(m)
	if err != nil {
		t.Fatal(err)
	}

	account := crypto.Account{
		PublicKey:  privateKey.Public().(ed25519.PublicKey),
		PrivateKey: privateKey,
		Address:    types.Address{},
	}

	copy(account.Address[:], account.PublicKey)

	out := &output{
		PrvHex:  hex.EncodeToString(account.PrivateKey),
		PubHex:  hex.EncodeToString(account.PublicKey),
		Addr:    account.Address.String(),
		KeyType: keyType,
	}

	if out.Addr != expectedAddr {
		t.Fatal("output addr does not match expected addr")
	}
}
