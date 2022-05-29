package run

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/kubetrail/algokey/pkg/flags"
	"github.com/kubetrail/bip32/pkg/keys"
	"github.com/kubetrail/bip39/pkg/prompts"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func MnemonicGen(cmd *cobra.Command, args []string) error {
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
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter seed key in hex: "); err != nil {
					return fmt.Errorf("failed to write to output: %w", err)
				}
			}
			key, err = keys.Read(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("failed to read seed from input: %w", err)
			}
		} else {
			key = args[0]
		}
	}

	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("failed to decode input key as hex string: %w", err)
	}

	mnemonicString, err := mnemonic.FromKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to generate 25-word mnemonic from key: %w", err)
	}

	privateKey, err = mnemonic.ToPrivateKey(mnemonicString)
	if err != nil {
		return fmt.Errorf("failed to generate private key from 25-word mnemonic: %w", err)
	}

	publicKey = privateKey.Public().(ed25519.PublicKey)

	account := crypto.Account{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Address:    types.Address{},
	}

	copy(account.Address[:], account.PublicKey)

	out := &output{
		Mnemonic: mnemonicString,
		PrvHex:   hex.EncodeToString(account.PrivateKey),
		PubHex:   hex.EncodeToString(account.PublicKey),
		Addr:     account.Address.String(),
		KeyType:  keyType,
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
