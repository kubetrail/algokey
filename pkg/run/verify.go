package run

import (
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

func Verify(cmd *cobra.Command, args []string) error {
	persistentFlags := getPersistentFlags(cmd)

	_ = viper.BindPFlag(flags.Hash, cmd.Flag(flags.Hash))
	_ = viper.BindPFlag(flags.Sign, cmd.Flag(flags.Sign))
	_ = viper.BindPFlag(flags.Key, cmd.Flag(flags.Key))

	hash := viper.GetString(flags.Hash)
	sign := viper.GetString(flags.Sign)
	key := viper.GetString(flags.Key)

	var verified bool

	prompt, err := prompts.Status()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	if len(key) == 0 {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter pub key: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}
		key, err = keys.Read(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("failed to read pub key from input: %w", err)
		}
	}

	if len(hash) == 0 {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter hash: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}
		hash, err = keys.Read(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("failed to read hash from input: %w", err)
		}
	}

	if len(sign) == 0 {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter sign: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}
		sign, err = keys.Read(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("failed to read signature from input: %w", err)
		}
	}

	if !keys.IsValidBase58String(hash) {
		return fmt.Errorf("hash is not a valid base58 string")
	}

	if !keys.IsValidBase58String(sign) {
		return fmt.Errorf("signature is not a valid base58 string")
	}

	publicKey, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("failed to decode input key as hex string: %w", err)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("expected public key len %d, received %d", ed25519.PublicKeySize, len(publicKey))
	}

	verified = ed25519.Verify(publicKey, base58.Decode(hash), base58.Decode(sign))

	type output struct {
		Verified bool `json:"verified" yaml:"verified"`
	}

	out := &output{Verified: verified}

	switch strings.ToLower(persistentFlags.OutputFormat) {
	case flags.OutputFormatNative:
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), verified); err != nil {
			return fmt.Errorf("failed to write signature verification to output: %w", err)
		}
	case flags.OutputFormatYaml:
		jb, err := yaml.Marshal(out)
		if err != nil {
			return fmt.Errorf("failed to serialize output to yaml: %w", err)
		}

		if _, err := fmt.Fprint(cmd.OutOrStdout(), string(jb)); err != nil {
			return fmt.Errorf("failed to write signature verification to output: %w", err)
		}
	case flags.OutputFormatJson:
		jb, err := json.Marshal(out)
		if err != nil {
			return fmt.Errorf("failed to serialize output to json: %w", err)
		}

		if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(jb)); err != nil {
			return fmt.Errorf("failed to write signature verification to output: %w", err)
		}
	default:
		return fmt.Errorf("failed to format in requested format, %s is not supported", persistentFlags.OutputFormat)
	}

	return nil
}
