package run

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/types"

	"github.com/kubetrail/algokey/pkg/flags"
	"github.com/kubetrail/bip32/pkg/keys"
	"github.com/kubetrail/bip39/pkg/prompts"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func Decode(cmd *cobra.Command, args []string) error {
	persistentFlags := getPersistentFlags(cmd)

	_ = viper.BindPFlag(flags.Key, cmd.Flag(flags.Key))

	key := viper.GetString(flags.Key)

	var publicKey ed25519.PublicKey
	var privateKey ed25519.PrivateKey

	prompt, err := prompts.Status()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	if len(key) == 0 {
		if len(args) == 0 {
			if prompt {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter pub key: "); err != nil {
					return fmt.Errorf("failed to write to output: %w", err)
				}
			}
			key, err = keys.Read(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("failed to read pub key from input: %w", err)
			}
		} else {
			key = args[0]
		}
	}

	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("failed to decode input key as hex string: %w", err)
	}

	switch len(keyBytes) {
	case ed25519.PublicKeySize:
	case ed25519.PrivateKeySize:
	default:
		return fmt.Errorf("expected key len to be either %d or %d", ed25519.PublicKeySize, ed25519.PrivateKeySize)
	}

	if len(keyBytes) == ed25519.PublicKeySize {
		publicKey = keyBytes
	}

	if len(keyBytes) == ed25519.PrivateKeySize {
		privateKey = keyBytes

		publicKey, _, err = ed25519.GenerateKey(bufio.NewReader(bytes.NewReader(keyBytes[:ed25519.SeedSize])))
		if err != nil {
			return fmt.Errorf("failed to generate keys: %w", err)
		}
	}

	account := crypto.Account{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Address:    types.Address{},
	}

	copy(account.Address[:], account.PublicKey)

	outPrv := fmt.Sprintf("%s", hex.EncodeToString(account.PrivateKey))
	outPub := fmt.Sprintf("%s", hex.EncodeToString(account.PublicKey))

	type output struct {
		Seed string `json:"seed,omitempty" yaml:"seed,omitempty"`
		Prv  string `json:"prv,omitempty" yaml:"prv,omitempty"`
		Pub  string `json:"pub,omitempty" yaml:"pub,omitempty"`
		Addr string `json:"addr,omitempty" yaml:"addr,omitempty"`
	}

	out := &output{
		Prv:  outPrv,
		Pub:  outPub,
		Addr: account.Address.String(),
	}

	switch strings.ToLower(persistentFlags.OutputFormat) {
	case flags.OutputFormatNative, flags.OutputFormatYaml:
		jb, err := yaml.Marshal(out)
		if err != nil {
			return fmt.Errorf("failed to serialize output to yaml: %w", err)
		}

		if _, err := fmt.Fprint(cmd.OutOrStdout(), string(jb)); err != nil {
			return fmt.Errorf("failed to write key to output: %w", err)
		}
	case flags.OutputFormatJson:
		jb, err := json.Marshal(out)
		if err != nil {
			return fmt.Errorf("failed to serialize output to json: %w", err)
		}

		if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(jb)); err != nil {
			return fmt.Errorf("failed to write key to output: %w", err)
		}
	default:
		return fmt.Errorf("failed to format in requested format, %s is not supported", persistentFlags.OutputFormat)
	}

	return nil
}
