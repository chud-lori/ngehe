package cmd

import (
	"fmt"
	"os"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/spf13/cobra"
)

var initOutput string

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Write a sample ngehe.yaml config",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := os.Stat(initOutput); err == nil {
			return fmt.Errorf("%s already exists; delete it or pass --out", initOutput)
		}
		if err := os.WriteFile(initOutput, []byte(config.Sample), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote sample config to %s\n", initOutput)
		return nil
	},
}

func init() {
	initCmd.Flags().StringVarP(&initOutput, "out", "o", "ngehe.yaml", "path to write sample config")
	rootCmd.AddCommand(initCmd)
}
