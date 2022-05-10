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

// hashCmd represents the hash command
var hashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Generate input hash",
	Long:  ``,
	RunE:  run.Hash,
}

func init() {
	rootCmd.AddCommand(hashCmd)
	f := hashCmd.Flags()

	f.String(flags.Filename, "", "Input file to generate hash for")
}
