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
	"github.com/spf13/cobra"
)

// mnemonicGenCmd represents the mnemonicGen command
var mnemonicGenCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate 25-word mnemonic for recovery",
	Long: `This command generates Algorand native
25-word mnemonic from seed.

Please note that this mnemonic is not compatible
as input for generating new keys using this tool
and should, therefore, be only used for recovering
wallet in apps that accept native 25-word Algorand
specific mnemonic.
`,
	RunE: run.MnemonicGen,
}

func init() {
	mnemonicCmd.AddCommand(mnemonicGenCmd)
	f := mnemonicGenCmd.Flags()

	f.String(flags.Key, "", "Seed in hex")
}
