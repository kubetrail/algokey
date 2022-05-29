package run

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/kubetrail/algokey/pkg/flags"
	"github.com/kubetrail/bip32/pkg/keys"
	"github.com/kubetrail/bip39/pkg/prompts"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func Sign(cmd *cobra.Command, args []string) error {
	persistentFlags := getPersistentFlags(cmd)

	_ = viper.BindPFlag(flags.Hash, cmd.Flag(flags.Hash))
	_ = viper.BindPFlag(flags.Key, cmd.Flag(flags.Key))

	hash := viper.GetString(flags.Hash)
	key := viper.GetString(flags.Key)

	prompt, err := prompts.Status()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	if len(key) == 0 {
		if prompt {
			if err := keys.Prompt(cmd.OutOrStdout()); err != nil {
				return fmt.Errorf("failed to prompt for key: %w", err)
			}
		}

		key, err = keys.Read(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("failed to read key from input: %w", err)
		}
	}

	if len(hash) == 0 {
		if prompt {
			if prompt {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter hash: "); err != nil {
					return fmt.Errorf("failed to write to output: %w", err)
				}
			}
			hash, err = keys.Read(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("failed to read hash input: %w", err)
			}
		}
	}

	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("failed to decode key as hex string: %w", err)
	}

	if len(keyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("expected private key size %d, received %d", ed25519.PrivateKeySize, len(keyBytes))
	}

	publicKey, privateKey, err := ed25519.GenerateKey(bufio.NewReader(bytes.NewReader(keyBytes[:ed25519.SeedSize])))
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 key from input key: %w", err)
	}

	if !bytes.Equal(keyBytes[ed25519.SeedSize:], publicKey) {
		return fmt.Errorf(
			"expected public key %s, received %s",
			hex.EncodeToString(publicKey),
			hex.EncodeToString(keyBytes[ed25519.SeedSize:]),
		)
	}

	if !keys.IsValidBase58String(hash) {
		return fmt.Errorf("hash is not a valid base58 string")
	}

	sign := ed25519.Sign(privateKey, base58.Decode(hash))
	signHex := base58.Encode(sign)

	type output struct {
		Sign string `json:"sign,omitempty" yaml:"sign,omitempty"`
	}

	out := &output{Sign: signHex}

	switch strings.ToLower(persistentFlags.OutputFormat) {
	case flags.OutputFormatNative:
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), signHex); err != nil {
			return fmt.Errorf("failed to write signature to output: %w", err)
		}
	case flags.OutputFormatYaml:
		jb, err := yaml.Marshal(out)
		if err != nil {
			return fmt.Errorf("failed to serialize output to yaml: %w", err)
		}

		if _, err := fmt.Fprint(cmd.OutOrStdout(), string(jb)); err != nil {
			return fmt.Errorf("failed to write signature to output: %w", err)
		}
	case flags.OutputFormatJson:
		jb, err := json.Marshal(out)
		if err != nil {
			return fmt.Errorf("failed to serialize output to json: %w", err)
		}

		if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(jb)); err != nil {
			return fmt.Errorf("failed to write signature to output: %w", err)
		}
	default:
		return fmt.Errorf("failed to format in requested format, %s is not supported", persistentFlags.OutputFormat)
	}

	return nil
}
