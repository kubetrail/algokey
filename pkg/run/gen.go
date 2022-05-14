package run

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/kubetrail/algokey/pkg/flags"
	"github.com/kubetrail/bip39/pkg/mnemonics"
	"github.com/kubetrail/bip39/pkg/passphrases"
	"github.com/kubetrail/bip39/pkg/prompts"
	"github.com/kubetrail/bip39/pkg/seeds"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

const (
	keyType = "ed25519"
)

type output struct {
	Seed    string `json:"seed,omitempty" yaml:"seed,omitempty"`
	PrvHex  string `json:"prvHex,omitempty" yaml:"prvHex,omitempty"`
	PubHex  string `json:"pubHex,omitempty" yaml:"pubHex,omitempty"`
	Addr    string `json:"addr,omitempty" yaml:"addr,omitempty"`
	KeyType string `json:"keyType,omitempty" yaml:"keyType,omitempty"`
}

func Gen(cmd *cobra.Command, args []string) error {
	persistentFlags := getPersistentFlags(cmd)

	_ = viper.BindPFlag(flags.UsePassphrase, cmd.Flag(flags.UsePassphrase))
	_ = viper.BindPFlag(flags.SkipMnemonicValidation, cmd.Flag(flags.SkipMnemonicValidation))
	_ = viper.BindPFlag(flags.DerivationPath, cmd.Flag(flags.DerivationPath))
	_ = viper.BindPFlag(flags.InputHexSeed, cmd.Flag(flags.InputHexSeed))
	_ = viper.BindPFlag(flags.MnemonicLanguage, cmd.Flag(flags.MnemonicLanguage))

	usePassphrase := viper.GetBool(flags.UsePassphrase)
	skipMnemonicValidation := viper.GetBool(flags.SkipMnemonicValidation)
	derivationPath := viper.GetString(flags.DerivationPath)
	inputHexSeed := viper.GetBool(flags.InputHexSeed)
	language := viper.GetString(flags.MnemonicLanguage)

	derivationPath = strings.ToLower(derivationPath)
	derivationPath = strings.ReplaceAll(derivationPath, "h", "'")

	prompt, err := prompts.Status()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	var passphrase string
	var seed []byte

	if inputHexSeed && usePassphrase {
		return fmt.Errorf("cannot use passphrase when entering seed")
	}

	if inputHexSeed && skipMnemonicValidation {
		return fmt.Errorf("cannot use --skip-mnemonic-validation when entering seed")
	}

	if !inputHexSeed {
		var mnemonic string
		if len(args) == 0 {
			if prompt {
				if err := mnemonics.Prompt(cmd.OutOrStdout()); err != nil {
					return fmt.Errorf("failed to write to output: %w", err)
				}
			}

			mnemonic, err = mnemonics.Read(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("failed to read mnemonic from input: %w", err)
			}
		} else {
			mnemonic = mnemonics.NewFromFields(args)
		}

		if !skipMnemonicValidation {
			if mnemonic, err = mnemonics.Translate(mnemonic, language, mnemonics.LanguageEnglish); err != nil {
				return fmt.Errorf("failed to translate mnemonic to English, alternatively try --skip-mnemonic-validation flag: %w", err)
			}
		} else {
			mnemonic = mnemonics.Tidy(mnemonic)
		}

		if usePassphrase {
			passphrase, err = passphrases.New(cmd.OutOrStdout())
			if err != nil {
				return fmt.Errorf("failed to get passphrase: %w", err)
			}
		}

		seed = seeds.New(mnemonic, passphrase)
	} else {
		if len(args) == 0 {
			if prompt {
				if err := seeds.Prompt(cmd.OutOrStdout()); err != nil {
					return fmt.Errorf("failed to prompt for seed: %w", err)
				}
			}

			seed, err = seeds.Read(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("invalid seed: %w", err)
			}
		} else {
			seed, err = hex.DecodeString(args[0])
			if err != nil {
				return fmt.Errorf("failed to decode seed: %w", err)
			}
		}

		if len(seed) != ed25519.SeedSize {
			return fmt.Errorf("seed length should be %d, received %d", ed25519.SeedSize, len(seed))
		}
	}

	if len(seed) < ed25519.SeedSize {
		return fmt.Errorf("seed length should be at least %d, received %d", ed25519.SeedSize, len(seed))
	}

	seed = seed[:ed25519.SeedSize]
	account, err := crypto.AccountFromPrivateKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return fmt.Errorf("failed to generate new account from private key: %w", err)
	}

	out := &output{
		Seed:    hex.EncodeToString(seed),
		PrvHex:  hex.EncodeToString(account.PrivateKey),
		PubHex:  hex.EncodeToString(account.PublicKey),
		Addr:    account.Address.String(),
		KeyType: keyType,
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
