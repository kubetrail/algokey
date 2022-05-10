/*
Copyright © 2022 kubetrail.io authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/kubetrail/algokey/pkg/flags"
	"github.com/kubetrail/algokey/pkg/run"
	"github.com/kubetrail/bip39/pkg/mnemonics"
	"github.com/spf13/cobra"
)

// genCmd represents the gen command
var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate key from mnemonic",
	Long: `This command generates private/public keys.

Mnemonic language can be specified from the following list:
1. English (default)
2. Japanese
3. ChineseSimplified
4. ChineseTraditional
5. Czech
6. French
7. Italian
8. Korean
9. Spanish

BIP-39 proposal: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

Please note that same keys will be generated for mnemonics from different languages
if the underlying entropy is the same. In other words, keys are always
generated after translating input mnemonic to English.
`,
	RunE: run.Gen,
}

func init() {
	rootCmd.AddCommand(genCmd)
	f := genCmd.Flags()

	// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
	// f.String(flags.DerivationPath, "m/44'/283'/0'/0/0", "Chain Derivation path")
	f.Bool(flags.UsePassphrase, false, "Prompt for secret passphrase")
	f.Bool(flags.InputHexSeed, false, "Treat input as hex seed instead of mnemonic")
	f.Bool(flags.SkipMnemonicValidation, false, "Skip mnemonic validation")
	f.String(flags.MnemonicLanguage, mnemonics.LanguageEnglish, "Mnemonic language")
}
